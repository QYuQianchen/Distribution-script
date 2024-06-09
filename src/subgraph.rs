use std::{
    fmt::{Debug, Formatter},
    env
};
use graphql_client::{GraphQLQuery, Response};
use alloy_primitives::{utils::parse_units, Address, U256};
use log::{debug, info};
use reqwest;
use crate::errors::SubgraphError;

// this is a workaround for the custom BigDecimal type in the subgraph schema
type BigDecimal = String;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/graphql/schema.graphql",
    query_path = "src/graphql/query.graphql",
    response_derives = "Debug, Serialize, Deserialize"
)]
pub struct EligibilityCheckQuery;

#[derive(Debug, Clone)]
pub struct SubgraphQuery {
    /// URL of the subgraph endpoint
    pub urls: Vec<String>,
    /// query parameters: validator address that owns some HOPR Safes and snapshot block number
    pub params: eligibility_check_query::Variables,
}

impl Debug for eligibility_check_query::Variables {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EligibilityCheckQueryVariables")
            .field("address", &self.owner)
            .field("block", &self.block)
            .finish()
    }
}

impl Clone for eligibility_check_query::Variables {
    fn clone(&self) -> eligibility_check_query::Variables {
        let eligibility_check_query::Variables { owner, block } = self;
            eligibility_check_query::Variables {
            owner: owner.clone(),
            block: *block,
        }
    }
}

impl SubgraphQuery {
    pub fn new(block: i64, owner: String) -> Self {
        let prod_api_key = env::var("SUBGRAPH_PROD_API_KEY").expect("Missing SUBGRAPH_PROD_API_KEY env var");
        let dev_account_id = env::var("SUBGRAPH_DEV_ACCOUNT_ID").expect("Missing SUBGRAPH_DEV_ACCOUNT_ID env var");

        let urls = vec![
            format!("https://gateway.thegraph.com/api/{}/subgraphs/id/FEQcaX9qfh31YL2K7rxRN5a3sr9rjMWkguJnby7StNRo", prod_api_key),
            format!("https://api.studio.thegraph.com/query/{}/hopr-nodes-dufour/version/latest", dev_account_id),
        ];

        let params = eligibility_check_query::Variables {
            owner: owner.to_lowercase(),
            block,
        };

        Self {
            urls,
            params
        }
    }

    /// Run queries on the subgraph endpoints. Use development endpoint as a backup
    pub async fn run(&self) -> Result<Response<eligibility_check_query::ResponseData>, Box<dyn std::error::Error>> {
        for url in &self.urls {
            info!("querying enpoint {:?}", &url);

            let request_body = EligibilityCheckQuery::build_query(self.params.clone());
            let client = reqwest::Client::new();
            let res = client.post(url)
                .json(&request_body)
                .send()
                .await;

            // catch errors and continue to the next subgraph endpoint if needed
            match res {
                Ok(res) => {
                    let response_body: Result<Response<eligibility_check_query::ResponseData>, _> = res.json().await;
                    match response_body {
                        Ok(response_body) => {
                            info!("{:#?}", response_body);

                            if response_body.data.is_none() {
                                debug!("No data in response body");
                                continue;
                            } else {
                                return Ok(response_body);
                            }
                        }
                        Err(_) => {
                            debug!("Failed to parse response body");
                            continue;
                        },
                    }
                }
                Err(_) => {
                    debug!("Failed to send request");
                    continue;
                },
            }
        }

        Err(Box::new(SubgraphError::AllRequestsFailed))
    }
}

#[derive(Default, Debug, Clone)]
pub struct Assets {
    pub balance: U256,
    pub safes: Vec<Address>,
    pub nodes: Vec<Address>,
    pub linked_owners: Vec<Address>,
}

impl Assets {
    pub fn from_response(response: Response<eligibility_check_query::ResponseData>) -> Result<Self, Box<dyn std::error::Error>> {
        let data = response.data.expect("cannot get data from response");
        
        let mut assets = Assets::default();

        if data.safe_owner_pairs.is_empty() {
            return Ok(assets);
        }

        for safe_owner_pair in data.safe_owner_pairs.iter() {
            // push each safe address to the safes vector
            assets.safes.push(safe_owner_pair.safe.id.parse::<Address>().unwrap());

            // parse wxHOPR balance to U256
            let balance:U256 = parse_units(&safe_owner_pair.safe.balance.wx_hopr_balance, "ether").expect("cannot parse wxHOPR balance").into();
            assets.balance = balance;

            // push node addresses to the nodes vector
            let mut node_addresses = safe_owner_pair.safe.registered_nodes_in_network_registry
                .iter()
                .map(
                    |node| node.node.id.parse::<Address>().unwrap()
                )
                .collect();
            assets.nodes.append(&mut node_addresses);

            // get all the unique linked owners
            for owner in safe_owner_pair.safe.owners.iter() {
                let owner_address = owner.owner.id.parse::<Address>().unwrap();
                if owner_address != safe_owner_pair.owner.id.parse::<Address>().unwrap() && !assets.linked_owners.iter().any(|x| x == &owner_address) {
                    assets.linked_owners.push(owner_address);
                }
            }
        }

        Ok(assets)
    }
    
}

#[cfg(test)]
pub mod tests {
    use std::str::FromStr;

    use super::*;
    use eligibility_check_query::ResponseData;
    use log::debug;
    // use eligibility_check_query::{EligibilityCheckQuerySafeOwnerPairs, EligibilityCheckQuerySafeOwnerPairsOwner, EligibilityCheckQuerySafeOwnerPairsSafe, EligibilityCheckQuerySafeOwnerPairsSafeBalance, EligibilityCheckQuerySafeOwnerPairsSafeOwners, EligibilityCheckQuerySafeOwnerPairsSafeOwnersOwner, EligibilityCheckQuerySafeOwnerPairsSafeRegisteredNodesInNetworkRegistry, EligibilityCheckQuerySafeOwnerPairsSafeRegisteredNodesInNetworkRegistryNode, ResponseData};
    // use serde::Serialize;
    use serde_json::json;

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[tokio::test]
    async fn cannot_run_query_with_wrong_keys() {
        init();

        env::set_var("SUBGRAPH_PROD_API_KEY", "abc123");
        env::set_var("SUBGRAPH_DEV_ACCOUNT_ID", "123abc");

        let subgraph_query = SubgraphQuery::new(34310645, "0x226d833075c26dbf9aa377de0363e435808953a4".into());

        // let data = subgraph_query.run().await.unwrap().data.expect("cannot query data");
        // debug!("{:?}", data);
        if subgraph_query.run().await.is_ok() {
            panic!("should not return data from subgraph");
        }

        env::remove_var("SUBGRAPH_PROD_API_KEY");
        env::remove_var("SUBGRAPH_DEV_ACCOUNT_ID");
    }

    #[tokio::test]
    async fn get_asset_from_returned_result() {
        init();

        let body: Response<ResponseData> = serde_json::from_value(json!({
            "data": {
                "safeOwnerPairs": [
                    {
                        "owner": {
                            "id": "0x226d833075c26dbf9aa377de0363e435808953a4",
                        },
                        "safe": {
                            "registeredNodesInNetworkRegistry": [
                                {
                                    "node": {
                                        "id": "0x06e7df53f76d5a0d3114e1ab6332a66b4e36cd86",
                                    },
                                },
                            ],
                            "owners": [
                                {
                                    "owner": {
                                        "id": "0x226d833075c26dbf9aa377de0363e435808953a4",
                                    },
                                },
                            ],
                            "id": "0x04d516f717ac1e45af3cd9694c37be10470cfb28",
                            "balance": {
                                "wxHoprBalance": "0",
                            },
                        },
                    },
                    {
                        "owner": {
                            "id": "0x226d833075c26dbf9aa377de0363e435808953a4",
                        },
                        "safe": {
                            "registeredNodesInNetworkRegistry": [
                                {
                                    "node": {
                                        "id": "0xf8c9c5dc27e843eb2d2c1e61501e421aeabd6acd",
                                    },
                                },
                            ],
                            "owners": [
                                {
                                    "owner": {
                                        "id": "0x226d833075c26dbf9aa377de0363e435808953a4",
                                    },
                                },
                            ],
                            "id": "0x0d9d6d05a37353a98a9beaaf2c852089793f5dd1",
                            "balance": {
                                "wxHoprBalance": "0",
                            },
                        },
                    },
                    {
                        "owner": {
                            "id": "0x226d833075c26dbf9aa377de0363e435808953a4",
                        },
                        "safe": {
                            "registeredNodesInNetworkRegistry": [
                                {
                                    "node": {
                                        "id": "0x037bebadd20b11816c0dbf5ee4905addbbac932f",
                                    },
                                },
                                {
                                    "node": {
                                        "id": "0x098c33a07281bfbb9010b22ea16e0500789fc6c3",
                                    },
                                },
                                {
                                    "node": {
                                        "id": "0xc440419850680e4f9ad8089b011915b24bdc0759",
                                    },
                                },
                            ],
                            "owners": [
                                {
                                    "owner": {
                                        "id": "0x226d833075c26dbf9aa377de0363e435808953a4",
                                    },
                                },
                                {
                                    "owner": {
                                        "id": "0x84aa5bbccfc1a77e99e81d45d4ffa2c1f5f7dea2",
                                    },
                                },
                            ],
                            "id": "0x989b9a0c195a7b416794070dfbc5dc8c1bcfb6d6",
                            "balance": {
                                "wxHoprBalance": "413311.33",
                            },
                        },
                    },
                ],
            },
        })).unwrap();
    
        let assets_from_body = Assets::from_response(body).unwrap();
        debug!("{:?}", assets_from_body);

        assert_eq!(assets_from_body.balance, U256::from_str("413311330000000000000000").unwrap());
        assert_eq!(assets_from_body.safes.len(), 3);
        assert_eq!(assets_from_body.nodes.len(), 5);
        assert_eq!(assets_from_body.linked_owners.len(), 1);
        // assert_eq!(assets_from_body.balance, Assets { 
        //     balance: U256::from("413311330000000000000000"), 
        //     safes: vec!["0x04d516f717ac1e45af3cd9694c37be10470cfb28", "0x0d9d6d05a37353a98a9beaaf2c852089793f5dd1", "0x989b9a0c195a7b416794070dfbc5dc8c1bcfb6d6"], 
        //     nodes: vec!["0x06e7df53f76d5a0d3114e1ab6332a66b4e36cd86", "0xf8c9c5dc27e843eb2d2c1e61501e421aeabd6acd", "0x037bebadd20b11816c0dbf5ee4905addbbac932f", "0x098c33a07281bfbb9010b22ea16e0500789fc6c3", "0xc440419850680e4f9ad8089b011915b24bdc0759"],
        //     linked_owners: vec!["0x84aa5bbccfc1a77e99e81d45d4ffa2c1f5f7dea2"] 
        // });
    }
}