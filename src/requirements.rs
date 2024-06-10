use std::{fmt::Debug, path::PathBuf};
use alloy_primitives::{utils::parse_units, Address, U256};
use csv::Reader;
use log::{debug, info};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};

use crate::subgraph::{AssetList, Assets};

/// Minimum requirements for an owner to be considered as eligible
pub struct Requirements {
    min_safe_balance: U256,
    min_running_node: u32,
}

impl Requirements {
    /// Create a new `Requirements` instance.
    pub fn new(min_safe_balance_in_eth: String, min_running_node: u32) -> Self {
        Self {
            min_safe_balance: parse_units(&min_safe_balance_in_eth, "ether").unwrap().into(),
            min_running_node,
        }
    }

    /// Check if the owner meets the minimum requirements.
    pub fn check_requirements(&self, safe_balance: &U256, running_nodes: &u32) -> bool {
        let check_balance = safe_balance >= &self.min_safe_balance;
        let check_nodes = running_nodes >= &self.min_running_node;
        debug!("Checking requirements: balance: {:?}, nodes: {:?}", check_balance, check_nodes);
        check_balance && check_nodes
    }

    /// Check if at least one asset fulfills the requirements.
    pub fn check_at_least_one_asset_fulfills_requirments(&self, assets: &Assets) -> bool {
        for (index, safe_balance) in assets.balance.iter().enumerate() {
            if self.check_requirements(safe_balance, &assets.nodes_count[index]) {
                return true;
            }
        }
        false
    }
}

/// Claim Entry
#[serde_as]
#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct Claim {
    #[serde_as(as = "DisplayFromStr")]
    pub owner: Address,
    #[serde_as(as = "DisplayFromStr")]
    pub safe: Address,
}

/// Claim History
#[derive(Debug, Deserialize, Serialize, Default)]
pub struct Claims {
    pub claims: Vec<Claim>,
}


impl Claims {
    /// Read the claims from a CSV file.
    pub fn read_from_csv(filename: &PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let file = std::fs::File::open(filename)?;
        let mut reader = Reader::from_reader(file);

        let mut claim_history = Self::default();
        for deserialized_iter in reader.deserialize() {
            let record: Claim = deserialized_iter?;
            claim_history.claims.push(record);
        }
        Ok(claim_history)
    }

    /// Write the claims to a CSV file.
    pub fn write_to_csv(&self, filename: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
        let file = std::fs::File::create(filename)?;
        let mut writer = csv::Writer::from_writer(file);
        for claim in &self.claims {
            writer.serialize(claim)?;
        }
        writer.flush()?;
        Ok(())
    }

    /// Add a claim to the claim history.
    pub fn add_claim(&mut self, claim: Claim) {
        self.claims.push(claim);
    }

    /// Add multiple claims to the claim history.
    pub fn add_claims(&mut self, claims: Vec<Claim>) {
        self.claims.extend(claims);
    }

    /// Check if some safe addresses are already claimed.
    pub fn check_claimed(&self, safes: &Vec<Address>) -> bool {
        safes.iter().any(|safe| self.claims.iter().any(|claim| claim.safe == *safe))
    }
}

/// Check the eligibility of the owners for claim
pub fn check_owners_eligibility(
    owners: &Vec<Address>,
    requirements: &Requirements,
    asset_list: &AssetList,
    claim_history: &mut Claims,
) -> Vec<Address> {
    let mut eligible_owners: Vec<Address> = vec![];
    // loop through safes
    for owner in owners {
        // for each owner, get their assets
        if let Some(owned_assets) = asset_list.asset_list.get(owner) {
            // none of the safe is already claimed
            if claim_history.check_claimed(&owned_assets.safes) {
                debug!("Owner: {:?} is not eligible for claim because some of its safes have already been claimed", owner);
                continue;
                
            }

            // check if at least one safe meets the requirements
            if requirements.check_at_least_one_asset_fulfills_requirments(owned_assets) {
                debug!("Owner: {:?} is eligible for claim", owner);
                // convert assets into claims and append to the claim history
                let claimed_safes = owned_assets.safes.iter().map(|safe| Claim {
                    owner: owner.to_owned(),
                    safe: safe.to_owned(),
                }).collect();
                claim_history.add_claims(claimed_safes);
                eligible_owners.push(owner.to_owned());
            } else {
                debug!("Owner: {:?} is not eligible for claim because none of its safes meet the requirements", owner);
                continue;
            }
        } else {
            debug!("Owner: {:?} is not eligible for claim because it does not have any safes", owner);
            continue;
        }
    }
    info!("Eligible owners: {:?}", eligible_owners);
    eligible_owners
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;
    use std::str::FromStr;
    use tempfile::tempdir;

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    fn write_csv(file: &std::fs::File) {
        let mut writer = csv::Writer::from_writer(file);
        writer.write_record(&["owner", "safe"]).unwrap();
        writer.write_record(&["0x226d833075c26dbf9aa377de0363e435808953a4", "0x0d9d6d05a37353a98a9beaaf2c852089793f5dd1"]).unwrap();
        writer.write_record(&["0x226d833075c26dbf9aa377de0363e435808953a4", "0x0bb7ac4a34a92d1b417b94dd8866e5b90e544c80"]).unwrap();
        writer.flush().unwrap();
    }

    #[test]
    fn test_requirements() {
        init();
        let requirements = Requirements::new("32".to_string(), 3);
        assert!(requirements.check_requirements(&U256::from_str("32000000000000000000").unwrap(), &3));
        assert!(!requirements.check_requirements(&U256::from_str("31000000000000000000").unwrap(), &3));
        assert!(!requirements.check_requirements(&U256::from_str("32000000000000000000").unwrap(), &2));
    }

    #[test]
    fn test_claim() {
        init();
        let claim = Claim {
            owner: address!("226d833075c26dbf9aa377de0363e435808953a4"),
            safe: address!("0d9d6d05a37353a98a9beaaf2c852089793f5dd1")
        };
        debug!("Claim: {:?}", claim);
    }

    #[test]
    fn test_read_claim_history() {
        init();
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("claim_history.csv");
        debug!("File: {:?}", &file_path);
        let file = std::fs::File::create(&file_path).unwrap();
        write_csv(&file);
        
        let claims = Claims::read_from_csv(&file_path).unwrap();
        assert_eq!(claims.claims.len(), 2);
        debug!("claims: {:?}", claims);
    }

    #[test]
    fn test_write_claim_history() {
        init();
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("claim_history.csv");
        debug!("File: {:?}", &file_path);
        let first_claims = Claims {
            claims: vec![
                Claim {
                    owner: address!("226d833075c26dbf9aa377de0363e435808953a4"),
                    safe: address!("0d9d6d05a37353a98a9beaaf2c852089793f5dd1")
                },
                Claim {
                    owner: address!("226d833075c26dbf9aa377de0363e435808953a4"),
                    safe: address!("0bb7ac4a34a92d1b417b94dd8866e5b90e544c80")
                }
            ]
        };
        first_claims.write_to_csv(&file_path).unwrap();
        debug!("first wrote claims: {:?}", first_claims);
        
        let first_read_claims = Claims::read_from_csv(&file_path).unwrap();
        debug!("first read claims: {:?}", first_read_claims);
        assert_eq!(first_read_claims.claims.len(), 2);
    
        let second_claims = Claims {
            claims: vec![
                Claim {
                    owner: address!("226d833075c26dbf9aa377de0363e435808953a4"),
                    safe: address!("0d9d6d05a37353a98a9beaaf2c852089793f5dd1")
                },
                Claim {
                    owner: address!("226d833075c26dbf9aa377de0363e435808953a4"),
                    safe: address!("0bb7ac4a34a92d1b417b94dd8866e5b90e544c80")
                },
                Claim {
                    owner: address!("226d833075c26dbf9aa377de0363e435808953a4"),
                    safe: address!("04d516f717ac1e45af3cd9694c37be10470cfb28")
                }
            ]
        };
        second_claims.write_to_csv(&file_path).unwrap();
        debug!("second wrote claims: {:?}", second_claims);

        let second_read_claims = Claims::read_from_csv(&file_path).unwrap();
        assert_eq!(second_read_claims.claims.len(), 3);
    }

    #[test]
    fn test_check_owners_eligibility_account_a_first() {
        init();

        // accounts A, B and C
        let owners = vec![
            address!("226d833075c26dbf9aa377de0363e435808953a4"),
            address!("a958674ceef9ec1dbb83b259b8dadbc9facdb82e"),
            address!("e0e6996b8d9f1ee7b08003b64c1442c7a1f1e753"),
        ];

        let requirements = Requirements::new("10000000".to_string(), 1);

        // accounts A and B have 1 shared safes
        // accounts A and C have 1 shared safe
        let asset_a = Assets {
            balance: vec![U256::from_str("10000000000000000000000000").unwrap(), U256::from_str("20000000000000000000000000").unwrap()],
            nodes_count: vec![1, 2],
            safes: vec![address!("0d9d6d05a37353a98a9beaaf2c852089793f5dd1"), address!("0bb7ac4a34a92d1b417b94dd8866e5b90e544c80")],
            linked_owners: vec![address!("a958674ceef9ec1dbb83b259b8dadbc9facdb82e")],
        };
        let asset_b = Assets {
            balance: vec![U256::from_str("10000000000000000000000000").unwrap()],
            nodes_count: vec![1],
            safes: vec![address!("0d9d6d05a37353a98a9beaaf2c852089793f5dd1")],
            linked_owners: vec![address!("226d833075c26dbf9aa377de0363e435808953a4")],
        };
        let asset_c = Assets {
            balance: vec![U256::from_str("20000000000000000000000000").unwrap()],
            nodes_count: vec![2],
            safes: vec![address!("0bb7ac4a34a92d1b417b94dd8866e5b90e544c80")],
            linked_owners: vec![address!("226d833075c26dbf9aa377de0363e435808953a4")],
        };
        let asset_list = AssetList {
            asset_list: vec![
                (address!("226d833075c26dbf9aa377de0363e435808953a4"), asset_a),
                (address!("a958674ceef9ec1dbb83b259b8dadbc9facdb82e"), asset_b),
                (address!("e0e6996b8d9f1ee7b08003b64c1442c7a1f1e753"), asset_c),
            ].into_iter().collect(),
        };

        let mut claim_history = Claims::default();

        let eligible_account = check_owners_eligibility(
            &owners,
            &requirements,
            &asset_list,
            &mut claim_history,
        );

        debug!("Eligible account: {:?}", eligible_account);
        assert_eq!(eligible_account.len(), 1);
    }

    #[test]
    fn test_check_owners_eligibility_account_a_last() {
        init();

        // accounts B, C and A
        let owners = vec![
            address!("a958674ceef9ec1dbb83b259b8dadbc9facdb82e"),
            address!("e0e6996b8d9f1ee7b08003b64c1442c7a1f1e753"),
            address!("226d833075c26dbf9aa377de0363e435808953a4"),
        ];

        let requirements = Requirements::new("10000000".to_string(), 1);

        // accounts A and B have 1 shared safes
        // accounts A and C have 1 shared safe
        let asset_a = Assets {
            balance: vec![U256::from_str("10000000000000000000000000").unwrap(), U256::from_str("20000000000000000000000000").unwrap()],
            nodes_count: vec![1, 2],
            safes: vec![address!("0d9d6d05a37353a98a9beaaf2c852089793f5dd1"), address!("0bb7ac4a34a92d1b417b94dd8866e5b90e544c80")],
            linked_owners: vec![address!("a958674ceef9ec1dbb83b259b8dadbc9facdb82e")],
        };
        let asset_b = Assets {
            balance: vec![U256::from_str("10000000000000000000000000").unwrap()],
            nodes_count: vec![1],
            safes: vec![address!("0d9d6d05a37353a98a9beaaf2c852089793f5dd1")],
            linked_owners: vec![address!("226d833075c26dbf9aa377de0363e435808953a4")],
        };
        let asset_c = Assets {
            balance: vec![U256::from_str("20000000000000000000000000").unwrap()],
            nodes_count: vec![2],
            safes: vec![address!("0bb7ac4a34a92d1b417b94dd8866e5b90e544c80")],
            linked_owners: vec![address!("226d833075c26dbf9aa377de0363e435808953a4")],
        };
        let asset_list = AssetList {
            asset_list: vec![
                (address!("226d833075c26dbf9aa377de0363e435808953a4"), asset_a),
                (address!("a958674ceef9ec1dbb83b259b8dadbc9facdb82e"), asset_b),
                (address!("e0e6996b8d9f1ee7b08003b64c1442c7a1f1e753"), asset_c),
            ].into_iter().collect(),
        };

        let mut claim_history = Claims::default();

        let eligible_account = check_owners_eligibility(
            &owners,
            &requirements,
            &asset_list,
            &mut claim_history,
        );

        assert_eq!(eligible_account.len(), 2);
    }
}