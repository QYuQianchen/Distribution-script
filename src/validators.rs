
use std::str::FromStr;
use alloy_primitives::Address;
use alloy_signer::Signature;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};

/// Signed deposited data for validator registration.
#[serde_as]
#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SignedDepositData{
    /// Address of the signer
    #[serde_as(as = "DisplayFromStr")]
    pub address: Address,
    /// Stringified JSON of the deposit data
    pub msg: String,
    /// Signature of the deposit data
    pub sig: String,
    /// Version of the deposit data
    #[serde_as(as = "DisplayFromStr")]
    pub version: u32,
}


impl SignedDepositData {
    /// Create a new `SignedDepositData` instance.
    pub fn new(address: Address, msg: String, sig: String, version: u32) -> Self {
        Self {
            address,
            msg,
            sig,
            version,
        }
    }

    /// Verify the signature of the `SignedDepositData`.
    pub fn verify(&self) -> bool {
        let signature = Signature::from_str(&self.sig).unwrap();
        signature.recover_address_from_msg(self.msg.as_bytes()).unwrap() == self.address
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use log::info;
    use std::{fs, io::Write};
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
            "sig": "0x2e6fe81ecb1790d6a7afbeea2a4fddd53a2cd481850db18b9489667deb26f4a86c62745b1551a97488b3613568e2fd196d20f4e1e0ee2247b89f2c244233591d1c",
            "version": "2"
        }"#;
        let resp: SignedDepositData = serde_json::from_str(s).unwrap();

        info!("Address {} signed {} with {}", resp.address, resp.msg, resp.sig);
        
    }

    #[test]
    fn verify_signed_message() {
        init();

        let s = r#"{
            "address": "0xc62727E27403aC22e9dBF73176013b94E3b138dF",
            "msg": "[{\"pubkey\": \"a096f540bcd7c0b798bd37f2bf06a6c2be9bb7e7572c8de83099ec2e423b1aa081aae701932eba3cf577b8a9f284870d\", \"withdrawal_credentials\": \"010000000000000000000000c62727e27403ac22e9dbf73176013b94e3b138df\", \"amount\": 32000000000, \"signature\": \"972797afd6f75e4e6c9ec6f4fd7305d1de5b227035b762b03983dc77083c128f64a2d8b3053ea7eccad231e8822b05d708ea3cc8e77e8adfb69ca61a4e36b85ee6f76d6e89784f3871410f322a2986d661a45c9b7e50abf4b39acc3e4aebb5e4\", \"deposit_message_root\": \"bb458a8df77a9e386d012bc214fb6afae4ced8cb84cfbf250a411dd6824a4e3c\", \"deposit_data_root\": \"a4a04cd5e1c6fc02059aa36805f01711511b2a75215eac6c5a916d152f1c426f\", \"fork_version\": \"00000064\", \"network_name\": \"gnosis\", \"deposit_cli_version\": \"2.3.0\"}]",
            "sig": "0x2e6fe81ecb1790d6a7afbeea2a4fddd53a2cd481850db18b9489667deb26f4a86c62745b1551a97488b3613568e2fd196d20f4e1e0ee2247b89f2c244233591d1c",
            "version": "2"
        }"#;
        let resp: SignedDepositData = serde_json::from_str(s).unwrap();

        assert!(resp.verify())
    }

    #[test]
    fn read_example_from_dir() {
        init();

        let tmp_dir = tempdir().unwrap();
        let file_path = tmp_dir.path().join("signed_deposit_data.json");

        info!("File path: {:?}", file_path);
        let mut tmp_file =  std::fs::File::create(file_path.clone()).unwrap();

        let s = r#"{
            "address": "0xc62727E27403aC22e9dBF73176013b94E3b138dF",
            "msg": "[{\"pubkey\": \"a096f540bcd7c0b798bd37f2bf06a6c2be9bb7e7572c8de83099ec2e423b1aa081aae701932eba3cf577b8a9f284870d\", \"withdrawal_credentials\": \"010000000000000000000000c62727e27403ac22e9dbf73176013b94e3b138df\", \"amount\": 32000000000, \"signature\": \"972797afd6f75e4e6c9ec6f4fd7305d1de5b227035b762b03983dc77083c128f64a2d8b3053ea7eccad231e8822b05d708ea3cc8e77e8adfb69ca61a4e36b85ee6f76d6e89784f3871410f322a2986d661a45c9b7e50abf4b39acc3e4aebb5e4\", \"deposit_message_root\": \"bb458a8df77a9e386d012bc214fb6afae4ced8cb84cfbf250a411dd6824a4e3c\", \"deposit_data_root\": \"a4a04cd5e1c6fc02059aa36805f01711511b2a75215eac6c5a916d152f1c426f\", \"fork_version\": \"00000064\", \"network_name\": \"gnosis\", \"deposit_cli_version\": \"2.3.0\"}]",
            "sig": "0x2e6fe81ecb1790d6a7afbeea2a4fddd53a2cd481850db18b9489667deb26f4a86c62745b1551a97488b3613568e2fd196d20f4e1e0ee2247b89f2c244233591d1c",
            "version": "2"
        }"#;

        writeln!(tmp_file, "{}", s).unwrap();

        info!("File written");

        info!(target: "signed_deposite_data_reader", "Reading path {}", &file_path.as_path().display().to_string());

        let a = fs::read_to_string(file_path.as_path().display().to_string()).unwrap();

        let resp: SignedDepositData = serde_json::from_str(&a).unwrap();

        info!("Address {} signed {} with {}", resp.address, resp.msg, resp.sig);

        info!("File read");
        drop(tmp_file);
        tmp_dir.close().unwrap();
    }
}
