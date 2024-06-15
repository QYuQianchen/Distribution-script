use alloy_primitives::{Address, FixedBytes, B256};
use alloy_signer::Signature;
use blst::{
    min_pk::{PublicKey, Signature as BLSSignature},
    BLST_ERROR,
};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use std::{fs, path::PathBuf, str::FromStr};
use tree_hash::{merkle_root, Hash256, PackedEncoding, TreeHash, TreeHashType, BYTES_PER_CHUNK};
use tree_hash_derive::TreeHash;
use validator::{Validate, ValidationError};

use crate::errors::ValidatorError;

fn validate_network_name(v: &String) -> Result<(), ValidationError> {
    if *v == "gnosis" {
        Ok(())
    } else {
        Err(ValidationError::new("Not supported network"))
    }
}

fn validate_withdrawal_credentials(v: &B256) -> Result<(), ValidationError> {
    if v[0] == 0 || v[0] == 1 {
        Ok(())
    } else {
        Err(ValidationError::new(
            "Invalid withdrawal credentials with wrong prefix",
        ))
    }
}

const DOMAIN_DEPOSIT: FixedBytes<4> = FixedBytes::<4>::new([3, 0, 0, 0]);
static DOMAIN_SEPARATION_TAG: &[u8; 43] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

#[derive(Debug, Serialize, Deserialize, Encode, Decode, TreeHash)]
struct ForkData {
    current_version: FixedBytes<4>,
    genesis_validators_root: FixedBytes<32>,
}

#[derive(Debug, Serialize, Deserialize, Encode, Decode, TreeHash)]
struct DepositMessage {
    pubkey: FixedBytes<48>,
    withdrawal_credentials: FixedBytes<32>,
    amount: u64,
}
#[derive(Debug, Serialize, Deserialize, Encode, Decode, TreeHash)]
struct SigningData {
    object_root: FixedBytes<32>,
    domain: FixedBytes<32>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CoreDepositDataSignature(FixedBytes<96>);

impl Encode for CoreDepositDataSignature {
    fn is_ssz_fixed_len() -> bool {
        <FixedBytes<96> as Encode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <FixedBytes<96> as Encode>::ssz_fixed_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.0.ssz_append(buf)
    }

    fn ssz_bytes_len(&self) -> usize {
        self.0.ssz_bytes_len()
    }
}

impl Decode for CoreDepositDataSignature {
    fn is_ssz_fixed_len() -> bool {
        <FixedBytes<96> as Decode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <FixedBytes<96> as Decode>::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Ok(Self(FixedBytes::from_ssz_bytes(bytes)?))
    }
}

impl TreeHash for CoreDepositDataSignature {
    fn tree_hash_type() -> TreeHashType {
        TreeHashType::Vector
    }

    fn tree_hash_packed_encoding(&self) -> PackedEncoding {
        unreachable!("Vector should never be packed.")
    }

    fn tree_hash_packing_factor() -> usize {
        unreachable!("Vector should never be packed.")
    }

    fn tree_hash_root(&self) -> Hash256 {
        let values_per_chunk = BYTES_PER_CHUNK;
        let minimum_chunk_count = (96 + values_per_chunk - 1) / values_per_chunk;
        merkle_root(self.0.as_ssz_bytes().as_slice(), minimum_chunk_count)
    }
}

#[derive(Debug, Serialize, Deserialize, Encode, Decode, TreeHash)]
struct CoreDepositData {
    pubkey: FixedBytes<48>,
    withdrawal_credentials: FixedBytes<32>,
    amount: u64,
    signature: CoreDepositDataSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Validate)]
pub struct DepositData {
    #[validate(range(min = 32000000000u64, max = 32000000000u64))]
    amount: u64,
    deposit_cli_version: String,
    deposit_data_root: FixedBytes<32>,
    deposit_message_root: FixedBytes<32>,
    fork_version: FixedBytes<4>,
    #[validate(custom(function = "validate_network_name"))]
    network_name: String,
    pubkey: FixedBytes<48>,
    signature: FixedBytes<96>,
    #[validate(custom(function = "validate_withdrawal_credentials"))]
    withdrawal_credentials: B256,
}

impl DepositData {
    /// Validate the deposit data, where it uses BLS signature https://eth2book.info/capella/part2/building_blocks/signatures/#bls-digital-signatures
    /// Reference implementation: https://github.com/gnosischain/validator-data-generator/blob/f90d73ac00c67a816f93ffb28954907f19dc4a07/staking_deposit/utils/validation.py#L43
    pub fn verify(&self) -> Result<(), Box<dyn std::error::Error>> {
        // compute the deposit domain
        let fork_data = ForkData {
            current_version: self.fork_version,
            genesis_validators_root: FixedBytes::<32>::default(),
        };
        let trimmed_fork_data_root: FixedBytes<28> =
            fork_data.tree_hash_root().as_bytes()[..28].try_into()?;
        debug!("Trimmed fork data root: {:?}", trimmed_fork_data_root);
        let deposit_domain: FixedBytes<32> = DOMAIN_DEPOSIT.concat_const(trimmed_fork_data_root);
        debug!("Deposit domain: {:?}", deposit_domain);

        // compute signing root
        let deposit_message = DepositMessage {
            pubkey: self.pubkey,
            withdrawal_credentials: self.withdrawal_credentials,
            amount: self.amount,
        };
        debug!("Deposit message: {:?}", deposit_message);
        let object_root: FixedBytes<32> = deposit_message.tree_hash_root().as_bytes().try_into()?;
        debug!("ssz_object tree hash: {:?}", object_root);
        let signing_data = SigningData {
            object_root,
            domain: deposit_domain,
        };
        let signing_root = signing_data.tree_hash_root();
        debug!("Signing root: {:?}", signing_root);

        // verify the signature as in
        // https://github.com/ethereum/py_ecc/blob/0569cb33aae15636d5afe7babed1930a8db6ab84/py_ecc/bls/ciphersuites.py#L298
        let public_key = PublicKey::from_bytes(&self.pubkey.0).map_err(|e| {
            ValidatorError::BLSVerificationError(format!("Error converting public key: {:?}", e))
        })?;
        let signature = BLSSignature::from_bytes(&self.signature.0).map_err(|e| {
            ValidatorError::BLSVerificationError(format!("Error converting signature: {:?}", e))
        })?;
        match signature.aggregate_verify(
            true,
            &[signing_root.as_bytes()],
            DOMAIN_SEPARATION_TAG,
            &[&public_key],
            true,
        ) {
            BLST_ERROR::BLST_SUCCESS => debug!("Signature verified"),
            e => {
                return Err(Box::new(ValidatorError::BLSVerificationError(format!(
                    "Error verifying signature: {:?}",
                    e
                ))))
            }
        }

        // verify deposit root
        let core_deposit_data = CoreDepositData {
            pubkey: self.pubkey,
            withdrawal_credentials: self.withdrawal_credentials,
            amount: self.amount,
            signature: CoreDepositDataSignature(self.signature),
        };
        let deposit_data_root = core_deposit_data.tree_hash_root();
        debug!("Deposit data root: {:?}", deposit_data_root);
        if deposit_data_root.0 != self.deposit_data_root.0 {
            return Err(Box::new(ValidatorError::BLSVerificationError(
                "Deposit data root does not match".to_string(),
            )));
        }

        info!("Deposit data verified: {:?}", &self);
        Ok(())
    }
}

/// Signed deposited data for validator registration.
#[serde_as]
#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq)]
pub struct SignedDepositData {
    /// Address of the signer
    #[serde_as(as = "DisplayFromStr")]
    pub address: Address,
    /// Stringified JSON of the deposit data
    pub msg: String,
    /// Signature of the deposit data
    pub sig: String,
}

impl SignedDepositData {
    /// Read the `SignedDepositData` from a file.
    pub fn read_from_file(file: PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(file.as_path().display().to_string())?;
        let resp: SignedDepositData = serde_json::from_str(&content)?;
        Ok(resp)
    }

    /// Verify the signature of the `SignedDepositData`, and the BLS signature of the deposit data without knowing the creation credential.
    /// Return the deposit data vector if the verification is successful.
    pub fn verify(&self) -> Result<Vec<DepositData>, Box<dyn std::error::Error>> {
        // Firstly, verify the outter ECSDA signature
        let signature = Signature::from_str(&self.sig)?;
        let recovered_address = signature.recover_address_from_msg(self.msg.as_bytes())?;

        if recovered_address != self.address {
            return Err(Box::new(ValidatorError::ECDSAVerficationError(
                "Recovered address does not match the signed address".to_string(),
            )));
        }

        // Secondly, verify the inner BLS signature of the deposit data, as implemented in
        // https://github.com/gnosischain/validator-data-generator/sblob/f90d73ac00c67a816f93ffb28954907f19dc4a07/staking_deposit/utils/validation.py#L43
        let deposit_data_vec: Vec<DepositData> = serde_json::from_str(&self.msg)?;
        info!("Deposit data contains {:?} entries", deposit_data_vec.len());

        // Only print warning if no deposit data found, but does not return error as it's checked by validation function
        if deposit_data_vec.is_empty() {
            warn!("No deposit data found");
        }

        // check BLS signature for each deposit data
        for deposit_data in deposit_data_vec.iter() {
            debug!("Verifying deposit data: {:?}", deposit_data);
            deposit_data.verify()?
        }

        Ok(deposit_data_vec)
    }

    /// Validate and verify the deposit data. Firstly verify the ECDSA and BLS signatures, then validate the deposit data.
    /// The deposit data must exactly have one element.
    /// Return the deposit data string if the validation is successful.
    pub fn validate_and_verify_data(&self) -> Result<DepositData, Box<dyn std::error::Error>> {
        let deposit_data_vec: Vec<DepositData> = self.verify()?;

        // deposit data vector must not be empty
        if deposit_data_vec.is_empty() {
            return Err(Box::new(ValidatorError::ValidationError(
                "No deposit data found".to_string(),
            )));
        }
        // deposit data vector must not have more than one element
        if deposit_data_vec.len() > 1 {
            return Err(Box::new(ValidatorError::ValidationError(
                "Multiple deposit data found".to_string(),
            )));
        }
        Ok(deposit_data_vec[0].clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use log::debug;
    use std::io::Write;
    use tempfile::tempdir;

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn serde_headers_response() {
        init();

        let s = r#"{
            "address": "0xc62727E27403aC22e9dBF73176013b94E3b138dF",
            "msg": "[{\"pubkey\": \"a096f540bcd7c0b798bd37f2bf06a6c2be9bb7e7572c8de83099ec2e423b1aa081aae701932eba3cf577b8a9f284870d\", \"withdrawal_credentials\": \"010000000000000000000000c62727e27403ac22e9dbf73176013b94e3b138df\", \"amount\": 32000000000, \"signature\": \"972797afd6f75e4e6c9ec6f4fd7305d1de5b227035b762b03983dc77083c128f64a2d8b3053ea7eccad231e8822b05d708ea3cc8e77e8adfb69ca61a4e36b85ee6f76d6e89784f3871410f322a2986d661a45c9b7e50abf4b39acc3e4aebb5e4\", \"deposit_message_root\": \"bb458a8df77a9e386d012bc214fb6afae4ced8cb84cfbf250a411dd6824a4e3c\", \"deposit_data_root\": \"a4a04cd5e1c6fc02059aa36805f01711511b2a75215eac6c5a916d152f1c426f\", \"fork_version\": \"00000064\", \"network_name\": \"gnosis\", \"deposit_cli_version\": \"2.3.0\"}]",
            "sig": "0x2e6fe81ecb1790d6a7afbeea2a4fddd53a2cd481850db18b9489667deb26f4a86c62745b1551a97488b3613568e2fd196d20f4e1e0ee2247b89f2c244233591d1c"
        }"#;
        let resp: SignedDepositData = serde_json::from_str(s).unwrap();

        debug!(
            "Address {} signed {} with {}",
            resp.address, resp.msg, resp.sig
        );
    }

    #[test]
    fn serde_headers_response_with_extra_field() {
        init();

        let s = r#"{
            "address": "0xc62727E27403aC22e9dBF73176013b94E3b138dF",
            "msg": "[{\"pubkey\": \"a096f540bcd7c0b798bd37f2bf06a6c2be9bb7e7572c8de83099ec2e423b1aa081aae701932eba3cf577b8a9f284870d\", \"withdrawal_credentials\": \"010000000000000000000000c62727e27403ac22e9dbf73176013b94e3b138df\", \"amount\": 32000000000, \"signature\": \"972797afd6f75e4e6c9ec6f4fd7305d1de5b227035b762b03983dc77083c128f64a2d8b3053ea7eccad231e8822b05d708ea3cc8e77e8adfb69ca61a4e36b85ee6f76d6e89784f3871410f322a2986d661a45c9b7e50abf4b39acc3e4aebb5e4\", \"deposit_message_root\": \"bb458a8df77a9e386d012bc214fb6afae4ced8cb84cfbf250a411dd6824a4e3c\", \"deposit_data_root\": \"a4a04cd5e1c6fc02059aa36805f01711511b2a75215eac6c5a916d152f1c426f\", \"fork_version\": \"00000064\", \"network_name\": \"gnosis\", \"deposit_cli_version\": \"2.3.0\"}]",
            "sig": "0x2e6fe81ecb1790d6a7afbeea2a4fddd53a2cd481850db18b9489667deb26f4a86c62745b1551a97488b3613568e2fd196d20f4e1e0ee2247b89f2c244233591d1c",
            "version": 2
        }"#;
        let resp: SignedDepositData = serde_json::from_str(s).unwrap();

        debug!(
            "Address {} signed {} with {}",
            resp.address, resp.msg, resp.sig
        );
    }

    #[test]
    fn read_example_from_dir() {
        init();

        let tmp_dir = tempdir().unwrap();
        let file_path = tmp_dir.path().join("signed_deposit_data.json");

        debug!("File path: {:?}", file_path);
        let mut tmp_file = std::fs::File::create(file_path.clone()).unwrap();

        let s = r#"{
            "address": "0xc62727E27403aC22e9dBF73176013b94E3b138dF",
            "msg": "[{\"pubkey\": \"a096f540bcd7c0b798bd37f2bf06a6c2be9bb7e7572c8de83099ec2e423b1aa081aae701932eba3cf577b8a9f284870d\", \"withdrawal_credentials\": \"010000000000000000000000c62727e27403ac22e9dbf73176013b94e3b138df\", \"amount\": 32000000000, \"signature\": \"972797afd6f75e4e6c9ec6f4fd7305d1de5b227035b762b03983dc77083c128f64a2d8b3053ea7eccad231e8822b05d708ea3cc8e77e8adfb69ca61a4e36b85ee6f76d6e89784f3871410f322a2986d661a45c9b7e50abf4b39acc3e4aebb5e4\", \"deposit_message_root\": \"bb458a8df77a9e386d012bc214fb6afae4ced8cb84cfbf250a411dd6824a4e3c\", \"deposit_data_root\": \"a4a04cd5e1c6fc02059aa36805f01711511b2a75215eac6c5a916d152f1c426f\", \"fork_version\": \"00000064\", \"network_name\": \"gnosis\", \"deposit_cli_version\": \"2.3.0\"}]",
            "sig": "0x2e6fe81ecb1790d6a7afbeea2a4fddd53a2cd481850db18b9489667deb26f4a86c62745b1551a97488b3613568e2fd196d20f4e1e0ee2247b89f2c244233591d1c"
        }"#;

        writeln!(tmp_file, "{}", s).unwrap();

        debug!("File written");

        let signed_deposit_data = SignedDepositData::read_from_file(file_path.clone()).unwrap();
        let verified_result = signed_deposit_data.verify().unwrap();
        assert_eq!(verified_result.len(), 1);
    }

    #[test]
    fn verify_ecdsa_and_bls_signatures_in_a_message() {
        init();

        let s = r#"{
            "address": "0x0416C8Bd44B83d33E62030F5d09f34d5bF345e9e",
            "msg": "[{\"pubkey\":\"b1824fe2c607db4d7f3566cb73371d5ad0da6a87f473279206b51f066174370359cf8a445dec403887f329ba3bc07a2d\",\"withdrawal_credentials\":\"00aa93d63eb5f25c558d47d860e7084f747c279feff3f5672d5e4f0693e66a48\",\"amount\":32000000000,\"signature\":\"97d1c9d17f5416efa839bedfae22729175982b9405a719cf29e3b51fdc435a995439cad1178bd79801cb5261a30e7a1d03c9b3142b078e94ed94262b7c666a27e35a08f545ab0dbf98eb1825d15ff757a9b4320e9e68cc39062d4344353f8959\",\"deposit_message_root\":\"fd13c4e49b3fc4976270d6fc7a2dd54d07b68257f2b8ca3a796fc956cd24573d\",\"deposit_data_root\":\"e13f76e86a647d8a4aec5e6b544641e2ab0e56457c167bdb28265860fc0d235f\",\"fork_version\":\"00000064\",\"network_name\":\"gnosis\",\"deposit_cli_version\":\"2.3.0\"}]",
            "sig": "0x5d2022b0134058dd96ee1f610b2ebb594266e0ace29324b6d062994fd33d7ad70299780dc551262fd2623dc16057fe11054a1b78fc14e68e5a7b0eba9f8f05f51b",
            "version": "2"
        }"#;
        let resp: SignedDepositData = serde_json::from_str(s).unwrap();
        let deposit_data_vec = resp.verify().unwrap();

        assert_eq!(deposit_data_vec.len(), 1);
    }

    #[test]
    fn verify_correct_ecdsa_signature_but_wrong_bls_signatures_in_a_message() {
        init();

        let s = r#"{
            "address": "0x0416C8Bd44B83d33E62030F5d09f34d5bF345e9e",
            "msg": "[{\"pubkey\":\"b1824fe2c607db4d7f3566cb73371d5ad0da6a87f473279206b51f066174370359cf8a445dec403887f329ba3bc07a2d\",\"withdrawal_credentials\":\"00aa93d63eb5f25c558d47d860e7084f747c279feff3f5672d5e4f0693e66a48\",\"amount\":32000000000,\"signature\":\"972797afd6f75e4e6c9ec6f4fd7305d1de5b227035b762b03983dc77083c128f64a2d8b3053ea7eccad231e8822b05d708ea3cc8e77e8adfb69ca61a4e36b85ee6f76d6e89784f3871410f322a2986d661a45c9b7e50abf4b39acc3e4aebb5e4\",\"deposit_message_root\":\"fd13c4e49b3fc4976270d6fc7a2dd54d07b68257f2b8ca3a796fc956cd24573d\",\"deposit_data_root\":\"e13f76e86a647d8a4aec5e6b544641e2ab0e56457c167bdb28265860fc0d235f\",\"fork_version\":\"00000064\",\"network_name\":\"gnosis\",\"deposit_cli_version\":\"2.3.0\"}]",
            "sig": "0x6714f30c52da069ac9ed02a8b4b40c6c1635f57df6a56d3209c4ddd18bb5cda43678ac9c53d81f50c362ebbfa3da1f2ff7e5a3730baff8ae9a06ac42ec35e1491b",
            "version": "2"
        }"#;
        let resp: SignedDepositData = serde_json::from_str(s).unwrap();

        match resp.verify() {
            Err(e) => {
                debug!("Error: {:?}", e);
                assert_eq!(
                    e.to_string(),
                    "BLS verification failed: 'Error verifying signature: BLST_VERIFY_FAIL'"
                );
            }
            Ok(deposit_data) => {
                debug!("Deposit data: {:?}", deposit_data);
                panic!("The deposit data should not be verified")
            }
        }
    }
    #[test]
    fn verify_correct_ecdsa_signature_and_correct_bls_signatures_but_wrong_deposit_data_root() {
        init();

        let s = r#"{
            "address": "0x0416C8Bd44B83d33E62030F5d09f34d5bF345e9e",
            "msg": "[{\"pubkey\":\"b1824fe2c607db4d7f3566cb73371d5ad0da6a87f473279206b51f066174370359cf8a445dec403887f329ba3bc07a2d\",\"withdrawal_credentials\":\"00aa93d63eb5f25c558d47d860e7084f747c279feff3f5672d5e4f0693e66a48\",\"amount\":32000000000,\"signature\":\"97d1c9d17f5416efa839bedfae22729175982b9405a719cf29e3b51fdc435a995439cad1178bd79801cb5261a30e7a1d03c9b3142b078e94ed94262b7c666a27e35a08f545ab0dbf98eb1825d15ff757a9b4320e9e68cc39062d4344353f8959\",\"deposit_message_root\":\"fd13c4e49b3fc4976270d6fc7a2dd54d07b68257f2b8ca3a796fc956cd24573d\",\"deposit_data_root\":\"000000e86a647d8a4aec5e6b544641e2ab0e56457c167bdb28265860fc0d235f\",\"fork_version\":\"00000064\",\"network_name\":\"gnosis\",\"deposit_cli_version\":\"2.3.0\"}]",
            "sig": "0x9180373d43b527d92a526329024eb8c132ab3d2c5381222f3245a1ccd9f24e206c2008a32c8d8ec53151c54a363f063e19bb1f56d601b70d446d296da554a5701b",
            "version": "2"
        }"#;
        let resp: SignedDepositData = serde_json::from_str(s).unwrap();

        match resp.verify() {
            Err(e) => {
                debug!("Error: {:?}", e);
                assert_eq!(
                    e.to_string(),
                    "BLS verification failed: 'Deposit data root does not match'"
                );
            }
            Ok(deposit_data) => {
                debug!("Deposit data: {:?}", deposit_data);
                panic!("The deposit data should not be verified")
            }
        }
    }

    #[test]
    fn verify_wrong_ecdsa_signature_but_correct_bls_signatures_in_a_message() {
        init();

        let s = r#"
        {
            "address": "0x0416C8Bd44B83d33E62030F5d09f34d5bF345e9e",
            "msg": "[{\"pubkey\":\"b1824fe2c607db4d7f3566cb73371d5ad0da6a87f473279206b51f066174370359cf8a445dec403887f329ba3bc07a2d\",\"withdrawal_credentials\":\"00aa93d63eb5f25c558d47d860e7084f747c279feff3f5672d5e4f0693e66a48\",\"amount\":32000000000,\"signature\":\"97d1c9d17f5416efa839bedfae22729175982b9405a719cf29e3b51fdc435a995439cad1178bd79801cb5261a30e7a1d03c9b3142b078e94ed94262b7c666a27e35a08f545ab0dbf98eb1825d15ff757a9b4320e9e68cc39062d4344353f8959\",\"deposit_message_root\":\"fd13c4e49b3fc4976270d6fc7a2dd54d07b68257f2b8ca3a796fc956cd24573d\",\"deposit_data_root\":\"e13f76e86a647d8a4aec5e6b544641e2ab0e56457c167bdb28265860fc0d235f\",\"fork_version\":\"00000064\",\"network_name\":\"gnosis\",\"deposit_cli_version\":\"2.3.0\"}]",
            "sig": "0xcf53dee9f8151bc9645b271b11ce87df0be0cb34f6139894ba84b3c465ab44026853538033ed6c6e3d25ab9be1b48ece5d1390bc4cfee2e61c31e0d8c3e0fddd1c",
            "version": "2"
        }"#;
        let resp: SignedDepositData = serde_json::from_str(s).unwrap();

        match resp.verify() {
            Err(e) => {
                debug!("Error: {:?}", e);
                assert_eq!(e.to_string(), "ECDSA verification failed: 'Recovered address does not match the signed address'");
            }
            Ok(deposit_data) => {
                debug!("Deposit data: {:?}", deposit_data);
                panic!("The deposit data should not be verified")
            }
        }
    }

    #[test]
    fn validate_one_deposit_data() {
        init();

        let s = r#"{
            "address": "0xc62727E27403aC22e9dBF73176013b94E3b138dF",
            "msg": "[{\"pubkey\": \"a096f540bcd7c0b798bd37f2bf06a6c2be9bb7e7572c8de83099ec2e423b1aa081aae701932eba3cf577b8a9f284870d\", \"withdrawal_credentials\": \"010000000000000000000000c62727e27403ac22e9dbf73176013b94e3b138df\", \"amount\": 32000000000, \"signature\": \"972797afd6f75e4e6c9ec6f4fd7305d1de5b227035b762b03983dc77083c128f64a2d8b3053ea7eccad231e8822b05d708ea3cc8e77e8adfb69ca61a4e36b85ee6f76d6e89784f3871410f322a2986d661a45c9b7e50abf4b39acc3e4aebb5e4\", \"deposit_message_root\": \"bb458a8df77a9e386d012bc214fb6afae4ced8cb84cfbf250a411dd6824a4e3c\", \"deposit_data_root\": \"a4a04cd5e1c6fc02059aa36805f01711511b2a75215eac6c5a916d152f1c426f\", \"fork_version\": \"00000064\", \"network_name\": \"gnosis\", \"deposit_cli_version\": \"2.3.0\"}]",
            "sig": "0x2e6fe81ecb1790d6a7afbeea2a4fddd53a2cd481850db18b9489667deb26f4a86c62745b1551a97488b3613568e2fd196d20f4e1e0ee2247b89f2c244233591d1c"
        }"#;
        let resp: SignedDepositData = serde_json::from_str(s).unwrap();
        let deposit_data_vec = resp.validate_and_verify_data().unwrap();

        assert_eq!(deposit_data_vec.pubkey.to_string(), "0xa096f540bcd7c0b798bd37f2bf06a6c2be9bb7e7572c8de83099ec2e423b1aa081aae701932eba3cf577b8a9f284870d");
    }

    #[test]
    fn fail_to_validate_empty_deposit_data() {
        init();

        let s = r#"{
            "address": "0x0416C8Bd44B83d33E62030F5d09f34d5bF345e9e",
            "msg": "[]",
            "sig": "0xdd821754627967c88e4f3ca61e4cbbd4fe1737dc66a85ebda8728b9eabf673e54596fc10ffe323a8b128cc6209b3f586902c5598afdba83a7d74e9e93bd5ce3f1c",
            "version": "2"
        }"#;
        let resp: SignedDepositData = serde_json::from_str(s).unwrap();
        match resp.validate_and_verify_data() {
            Err(e) => {
                debug!("Error: {:?}", e);
                assert_eq!(e.to_string(), "validation failed: 'No deposit data found'");
            }
            _ => panic!("Parsed invalid data"),
        }
    }

    #[test]
    fn fail_to_validate_multiple_deposit_data() {
        init();

        let s = r#"{
            "address": "0x0416C8Bd44B83d33E62030F5d09f34d5bF345e9e",
            "msg": "[{\"pubkey\":\"b1824fe2c607db4d7f3566cb73371d5ad0da6a87f473279206b51f066174370359cf8a445dec403887f329ba3bc07a2d\",\"withdrawal_credentials\":\"00aa93d63eb5f25c558d47d860e7084f747c279feff3f5672d5e4f0693e66a48\",\"amount\":32000000000,\"signature\":\"97d1c9d17f5416efa839bedfae22729175982b9405a719cf29e3b51fdc435a995439cad1178bd79801cb5261a30e7a1d03c9b3142b078e94ed94262b7c666a27e35a08f545ab0dbf98eb1825d15ff757a9b4320e9e68cc39062d4344353f8959\",\"deposit_message_root\":\"fd13c4e49b3fc4976270d6fc7a2dd54d07b68257f2b8ca3a796fc956cd24573d\",\"deposit_data_root\":\"e13f76e86a647d8a4aec5e6b544641e2ab0e56457c167bdb28265860fc0d235f\",\"fork_version\":\"00000064\",\"network_name\":\"gnosis\",\"deposit_cli_version\":\"2.3.0\"},{\"pubkey\":\"ad8fffa3e633f4261b24ea0254d03877582a53aa8485008403c4fb9e1215037e334c0cb01e442f6d64b812b51c7b66cd\",\"withdrawal_credentials\":\"008887be92ce6d975a216ded51a631bbbaf79b352de8a67896b46567484ef38c\",\"amount\":32000000000,\"signature\":\"ab1b63fa255ba53d10a7d8deffb2b2f9253505bc568142f43a76ee3956e390b3d1545e4873dbb7142b2222d5a208aff605172fec7ea5301b1e62bea1e848df8985a74b4d36501aa39c7e600f9e0c503e01bdceddc8d29c089af83b9d1bac0296\",\"deposit_message_root\":\"9029c8ba5963ef3e78ed953d59dce533d6fc4de167658cf0b3683b376f668453\",\"deposit_data_root\":\"3afa43f3cf6a356242b3683c54fae5bd7204fab072b5c7c75a416b760007e714\",\"fork_version\":\"00000064\",\"network_name\":\"gnosis\",\"deposit_cli_version\":\"2.3.0\"}]",
            "sig": "0xf80587360d321749f0549169e82e9abd8b046d77ee96eea665233e53f9b3ff5e6b3ada462fc168fc34ba26ea9a3349f1c02b7df013d23ae838708b7945dcf5331b",
            "version": "2"
        }"#;
        let resp: SignedDepositData = serde_json::from_str(s).unwrap();
        match resp.validate_and_verify_data() {
            Err(e) => {
                debug!("Error: {:?}", e);
                assert_eq!(
                    e.to_string(),
                    "validation failed: 'Multiple deposit data found'"
                );
            }
            _ => panic!("Parsed invalid data"),
        }
    }
}
