use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::collections::LookupMap;
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{env, near_bindgen, AccountId, PanicOnDefault};

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Clone)]
#[borsh(crate = "near_sdk::borsh")]
#[serde(crate = "near_sdk::serde")]
pub struct SecurityReportRecord {
    pub report_id: String,
    pub report_hash: String, // 64-character SHA-256 hash
    pub target: String,
    pub risk_score: u8,
    pub block_height: u64,
    pub timestamp_ns: u64,
    pub registrar: AccountId,
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
#[borsh(crate = "near_sdk::borsh")]
pub struct TrustGuardRegistry {
    pub owner_id: AccountId,
    pub reports_by_hash: LookupMap<String, SecurityReportRecord>,
    pub reports_by_id: LookupMap<String, SecurityReportRecord>,
    pub total_reports: u64,
}

impl near_sdk::state::ContractState for TrustGuardRegistry {}

#[near_bindgen]
impl TrustGuardRegistry {
    #[init]
    pub fn new(owner_id: Option<AccountId>) -> Self {
        assert!(!env::state_exists(), "Contract is already initialized");
        Self {
            owner_id: owner_id.unwrap_or_else(env::predecessor_account_id),
            reports_by_hash: LookupMap::new(b"h"),
            reports_by_id: LookupMap::new(b"i"),
            total_reports: 0,
        }
    }

    /// Anchors a new security report hash to the NEAR blockchain.
    /// STRICT ACCESS CONTROL: Only authorized owner/relayer account can call this.
    /// Rejects duplicate submissions and validates format.
    pub fn register_report(
        &mut self,
        report_id: String,
        report_hash: String,
        target: String,
        risk_score: u8,
    ) -> SecurityReportRecord {
        let caller = env::predecessor_account_id();

        // 1. Strict Access Control: only owner or authorized relayer
        assert_eq!(
            caller, self.owner_id,
            "Unauthorized: Only the contract owner or authorized relayer can register reports"
        );

        let normalized_hash = report_hash.to_lowercase().trim().to_string();

        // 2. Validate hash length and hex format (SHA-256 is 64 hex characters)
        assert_eq!(
            normalized_hash.len(),
            64,
            "Invalid report hash length. Must be a 64-character SHA-256 hex string"
        );
        assert!(
            normalized_hash.chars().all(|c| c.is_ascii_hexdigit()),
            "Invalid report hash. Must contain only valid hexadecimal characters"
        );

        // 3. Prevent duplicate submissions
        assert!(
            !self.reports_by_hash.contains_key(&normalized_hash),
            "Security report hash is already permanently registered on NEAR"
        );

        assert!(
            !self.reports_by_id.contains_key(&report_id),
            "Report ID already exists"
        );

        assert!(risk_score <= 100, "Risk score must be between 0 and 100");

        let record = SecurityReportRecord {
            report_id: report_id.clone(),
            report_hash: normalized_hash.clone(),
            target,
            risk_score,
            block_height: env::block_height(),
            timestamp_ns: env::block_timestamp(),
            registrar: caller,
        };

        self.reports_by_hash.insert(&normalized_hash, &record);
        self.reports_by_id.insert(&report_id, &record);
        self.total_reports += 1;

        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"trustguard\",\"version\":\"1.0.0\",\"event\":\"report_anchored\",\"data\":{{\"report_id\":\"{}\",\"report_hash\":\"{}\",\"block_height\":{}}}}}",
            report_id, normalized_hash, record.block_height
        ));

        record
    }

    /// Public read-only: Verifies if a given SHA-256 report hash exists on NEAR
    pub fn verify_report(&self, report_hash: String) -> bool {
        let normalized_hash = report_hash.to_lowercase().trim().to_string();
        self.reports_by_hash.contains_key(&normalized_hash)
    }

    /// Public read-only: Retrieves the full report record by its SHA-256 hash
    pub fn get_report(&self, report_hash: String) -> Option<SecurityReportRecord> {
        let normalized_hash = report_hash.to_lowercase().trim().to_string();
        self.reports_by_hash.get(&normalized_hash)
    }

    /// Public read-only: Retrieves the full report record by its human-readable Report ID
    pub fn get_report_by_id(&self, report_id: String) -> Option<SecurityReportRecord> {
        self.reports_by_id.get(&report_id)
    }

    /// Public read-only: Returns the total number of security reports anchored on-chain
    pub fn get_total_reports(&self) -> u64 {
        self.total_reports
    }

    /// Public read-only: Returns current owner / authorized relayer AccountId
    pub fn get_owner(&self) -> AccountId {
        self.owner_id.clone()
    }

    /// Restricted: Allows owner to transfer ownership or rotate relayer
    pub fn set_owner(&mut self, new_owner: AccountId) {
        assert_eq!(
            env::predecessor_account_id(),
            self.owner_id,
            "Unauthorized: Only current owner can transfer ownership"
        );
        self.owner_id = new_owner;
    }
}

/* ==========================================================================
   Contract Unit Tests
   ========================================================================== */
#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

    fn get_context(predecessor: &str) -> VMContextBuilder {
        let mut builder = VMContextBuilder::new();
        builder
            .predecessor_account_id(predecessor.parse().unwrap())
            .current_account_id("registry.near".parse().unwrap())
            .block_height(100_000)
            .block_timestamp(1_600_000_000_000_000_000);
        builder
    }

    #[test]
    fn test_register_and_verify_by_authorized_owner() {
        let context = get_context("relayer.testnet");
        testing_env!(context.build());

        let mut contract = TrustGuardRegistry::new(Some("relayer.testnet".parse().unwrap()));
        let sample_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string();

        let record = contract.register_report(
            "TG-REP-001".to_string(),
            sample_hash.clone(),
            "aurora.near".to_string(),
            10,
        );

        assert_eq!(record.report_id, "TG-REP-001");
        assert_eq!(record.risk_score, 10);
        assert_eq!(record.registrar, "relayer.testnet".parse::<AccountId>().unwrap());
        assert_eq!(contract.get_total_reports(), 1);
        assert!(contract.verify_report(sample_hash.clone()));

        let retrieved = contract.get_report(sample_hash).unwrap();
        assert_eq!(retrieved.target, "aurora.near");
        assert_eq!(retrieved.risk_score, 10);

        let by_id = contract.get_report_by_id("TG-REP-001".to_string()).unwrap();
        assert_eq!(by_id.report_hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    #[should_panic(expected = "Unauthorized: Only the contract owner or authorized relayer can register reports")]
    fn test_reject_unauthorized_registration() {
        let context = get_context("attacker.testnet");
        testing_env!(context.build());

        let mut contract = TrustGuardRegistry::new(Some("relayer.testnet".parse().unwrap()));
        let sample_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string();

        // Attacker attempts to register report -> must panic
        contract.register_report("TG-01".to_string(), sample_hash, "target.near".to_string(), 20);
    }

    #[test]
    #[should_panic(expected = "Security report hash is already permanently registered on NEAR")]
    fn test_prevent_duplicate_registration() {
        let context = get_context("relayer.testnet");
        testing_env!(context.build());

        let mut contract = TrustGuardRegistry::new(Some("relayer.testnet".parse().unwrap()));
        let sample_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string();

        contract.register_report("TG-01".to_string(), sample_hash.clone(), "target.near".to_string(), 20);
        // Duplicate registration must panic
        contract.register_report("TG-02".to_string(), sample_hash, "target.near".to_string(), 20);
    }

    #[test]
    #[should_panic(expected = "Invalid report hash. Must contain only valid hexadecimal characters")]
    fn test_reject_invalid_hex_hash() {
        let context = get_context("relayer.testnet");
        testing_env!(context.build());

        let mut contract = TrustGuardRegistry::new(Some("relayer.testnet".parse().unwrap()));
        // 64 characters but non-hex 'Z'
        let invalid_hash = "z3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string();

        contract.register_report("TG-01".to_string(), invalid_hash, "target.near".to_string(), 20);
    }

    #[test]
    fn test_unregistered_hash_returns_false() {
        let context = get_context("relayer.testnet");
        testing_env!(context.build());

        let contract = TrustGuardRegistry::new(Some("relayer.testnet".parse().unwrap()));
        let unknown_hash = "0000000000000000000000000000000000000000000000000000000000000000".to_string();

        assert!(!contract.verify_report(unknown_hash.clone()));
        assert!(contract.get_report(unknown_hash).is_none());
    }

    #[test]
    fn test_ownership_transfer() {
        let context = get_context("relayer.testnet");
        testing_env!(context.build());

        let mut contract = TrustGuardRegistry::new(Some("relayer.testnet".parse().unwrap()));
        assert_eq!(contract.get_owner(), "relayer.testnet".parse::<AccountId>().unwrap());

        contract.set_owner("new_relayer.testnet".parse().unwrap());
        assert_eq!(contract.get_owner(), "new_relayer.testnet".parse::<AccountId>().unwrap());
    }
}
