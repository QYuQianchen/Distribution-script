use crate::errors::SubgraphError;
use alloy_primitives::{utils::parse_units, Address, U256};
use graphql_client::{GraphQLQuery, Response};
use log::{debug, info, warn};
use reqwest;
use std::{
    collections::HashMap,
    env,
    fmt::{Debug, Formatter},
};

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
            .field("addrs", &self.addrs)
            .field("block", &self.block)
            .finish()
    }
}

impl Clone for eligibility_check_query::Variables {
    fn clone(&self) -> eligibility_check_query::Variables {
        let eligibility_check_query::Variables { addrs, block } = self;
        eligibility_check_query::Variables {
            addrs: addrs.clone(),
            block: *block,
        }
    }
}

impl SubgraphQuery {
    pub fn new(block: i64, owner_addresses: &[Address]) -> Self {
        let prod_api_key =
            env::var("SUBGRAPH_PROD_API_KEY").expect("Missing SUBGRAPH_PROD_API_KEY env var");
        let dev_account_id =
            env::var("SUBGRAPH_DEV_ACCOUNT_ID").expect("Missing SUBGRAPH_DEV_ACCOUNT_ID env var");

        let urls = vec![
            format!("https://gateway.thegraph.com/api/{}/subgraphs/id/FEQcaX9qfh31YL2K7rxRN5a3sr9rjMWkguJnby7StNRo", prod_api_key),
            format!("https://api.studio.thegraph.com/query/{}/hopr-nodes-dufour/version/latest", dev_account_id),
        ];

        let params = eligibility_check_query::Variables {
            addrs: Some(
                owner_addresses
                    .iter()
                    .map(|addr| addr.to_string().to_lowercase())
                    .collect::<Vec<String>>()
                    .to_owned(),
            ),
            block,
        };

        Self { urls, params }
    }

    /// Run queries on the subgraph endpoints. Use development endpoint as a backup
    pub async fn run(
        &self,
    ) -> Result<Response<eligibility_check_query::ResponseData>, Box<dyn std::error::Error>> {
        for url in &self.urls {
            info!("querying enpoint {:?}", &url);

            let request_body = EligibilityCheckQuery::build_query(self.params.clone());
            let client = reqwest::Client::new();
            let res = client.post(url).json(&request_body).send().await;

            // catch errors and continue to the next subgraph endpoint if needed
            match res {
                Ok(res) => {
                    let response_body: Result<Response<eligibility_check_query::ResponseData>, _> =
                        res.json().await;
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
                        }
                    }
                }
                Err(_) => {
                    debug!("Failed to send request");
                    continue;
                }
            }
        }

        Err(Box::new(SubgraphError::AllRequestsFailed))
    }
}

/// Assets of a single owner
#[derive(Default, Debug, Clone)]
pub struct Assets {
    pub balance: Vec<U256>,
    pub safes: Vec<Address>,
    pub nodes_count: Vec<u32>,
    pub linked_owners: Vec<Address>,
}

impl Assets {
    pub fn from_response(
        pairs: Vec<&eligibility_check_query::EligibilityCheckQuerySafeOwnerPairs>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut assets = Assets::default();

        if pairs.is_empty() {
            return Ok(assets);
        }

        for safe_owner_pair in pairs.iter() {
            // push each safe address to the safes vector
            assets
                .safes
                .push(safe_owner_pair.safe.id.parse::<Address>()?);

            // parse wxHOPR balance to U256
            let balance: U256 = parse_units(&safe_owner_pair.safe.balance.wx_hopr_balance, "ether")
                .expect("cannot parse wxHOPR balance")
                .into();
            assets.balance.push(balance);

            // push node addresses to the nodes vector
            let node_counts = safe_owner_pair
                .safe
                .registered_nodes_in_network_registry
                .len() as u32;
            assets.nodes_count.push(node_counts);

            // get all the unique linked owners
            for owner in safe_owner_pair.safe.owners.iter() {
                let owner_address = owner.owner.id.parse::<Address>()?;
                if owner_address != safe_owner_pair.owner.id.parse::<Address>()?
                    && !assets.linked_owners.iter().any(|x| x == &owner_address)
                {
                    assets.linked_owners.push(owner_address);
                }
            }
        }

        Ok(assets)
    }
}

/// hashmap of address to assets
#[derive(Default, Debug, Clone)]
pub struct AssetList {
    pub asset_list: HashMap<Address, Assets>,
}

impl AssetList {
    pub fn from_response(
        &mut self,
        response: Response<eligibility_check_query::ResponseData>,
    ) -> Result<&mut Self, Box<dyn std::error::Error>> {
        let data = response.data.expect("cannot get data from response");

        if data.safe_owner_pairs.is_empty() {
            return Ok(self);
        }

        // get all the owners
        let owners = data
            .safe_owner_pairs
            .iter()
            .fold(vec![] as Vec<Address>, |mut acc, x| {
                let address = x.owner.id.parse::<Address>();
                match address {
                    Ok(address) => {
                        if !acc.iter().any(|y| y == &address) {
                            acc.push(address);
                        }
                    }
                    Err(e) => {
                        warn!("cannot parse address {:?}", e);
                    }
                }
                acc
            });
        info!("unique owners {:?}", owners);

        // for each owner, get the assets
        for owner in owners {
            let owner_response = data
                .safe_owner_pairs
                .iter()
                .filter(|&safe_owner_pair| {
                    let address = safe_owner_pair.owner.id.parse::<Address>();
                    match address {
                        Ok(address) => address.eq(&owner),
                        Err(_) => false,
                    }
                })
                .collect::<Vec<&eligibility_check_query::EligibilityCheckQuerySafeOwnerPairs>>();

            debug!("owner {:?} owner_response {:?}", &owner, &owner_response);

            let assets =
                Assets::from_response(owner_response).expect("cannot get assets from response");
            info!("owner {:?} has assets {:?}", &owner, &assets);
            self.asset_list.insert(owner, assets);
        }
        Ok(self)
    }
}

#[cfg(test)]
pub mod tests {
    use std::str::FromStr;

    use super::*;
    use alloy_primitives::address;
    use eligibility_check_query::ResponseData;
    use log::debug;
    use serde_json::json;

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[tokio::test]
    async fn cannot_run_query_with_wrong_keys() {
        init();

        env::set_var("SUBGRAPH_PROD_API_KEY", "abc123");
        env::set_var("SUBGRAPH_DEV_ACCOUNT_ID", "123abc");

        let subgraph_query = SubgraphQuery::new(
            34310645,
            &vec![address!("226d833075c26dbf9aa377de0363e435808953a4")],
        );

        // let data = subgraph_query.run().await?.data.expect("cannot query data");
        // debug!("{:?}", data);
        if subgraph_query.run().await.is_ok() {
            panic!("should not return data from subgraph");
        }

        env::remove_var("SUBGRAPH_PROD_API_KEY");
        env::remove_var("SUBGRAPH_DEV_ACCOUNT_ID");
    }

    #[tokio::test]
    async fn get_asset_from_parsed_result() {
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
        }))
        .unwrap();

        let assets_from_body =
            Assets::from_response(body.data.unwrap().safe_owner_pairs.iter().collect()).unwrap();
        debug!("{:?}", assets_from_body);

        assert_eq!(assets_from_body.balance.len(), 3);
        assert_eq!(
            assets_from_body.balance[2],
            U256::from_str("413311330000000000000000").unwrap()
        );
        assert_eq!(assets_from_body.safes.len(), 3);
        assert_eq!(assets_from_body.nodes_count.len(), 3);
        assert_eq!(assets_from_body.nodes_count[0], 1);
        assert_eq!(assets_from_body.nodes_count[1], 1);
        assert_eq!(assets_from_body.nodes_count[2], 3);
        assert_eq!(assets_from_body.linked_owners.len(), 1);
    }

    #[tokio::test]
    async fn get_asset_from_returned_result() {
        init();

        let body: Response<ResponseData> = serde_json::from_value(json!({
            "data": {
              "safeOwnerPairs": [
                {
                  "owner": {
                    "id": "0x226d833075c26dbf9aa377de0363e435808953a4"
                  },
                  "safe": {
                    "registeredNodesInNetworkRegistry": [
                      {
                        "node": {
                          "id": "0x06e7df53f76d5a0d3114e1ab6332a66b4e36cd86"
                        }
                      }
                    ],
                    "owners": [
                      {
                        "owner": {
                          "id": "0x226d833075c26dbf9aa377de0363e435808953a4"
                        }
                      }
                    ],
                    "id": "0x04d516f717ac1e45af3cd9694c37be10470cfb28",
                    "balance": {
                      "wxHoprBalance": "0"
                    }
                  }
                },
                {
                  "owner": {
                    "id": "0x01bfbcb6a2924b083969ce6237adbbf3bfa7de13"
                  },
                  "safe": {
                    "registeredNodesInNetworkRegistry": [
                      {
                        "node": {
                          "id": "0xb57ff887e4822f957b47a4a72742202fb0bfc7f3"
                        }
                      }
                    ],
                    "owners": [
                      {
                        "owner": {
                          "id": "0x01bfbcb6a2924b083969ce6237adbbf3bfa7de13"
                        }
                      }
                    ],
                    "id": "0x0bb7ac4a34a92d1b417b94dd8866e5b90e544c80",
                    "balance": {
                      "wxHoprBalance": "0"
                    }
                  }
                },
                {
                  "owner": {
                    "id": "0x226d833075c26dbf9aa377de0363e435808953a4"
                  },
                  "safe": {
                    "registeredNodesInNetworkRegistry": [
                      {
                        "node": {
                          "id": "0xf8c9c5dc27e843eb2d2c1e61501e421aeabd6acd"
                        }
                      }
                    ],
                    "owners": [
                      {
                        "owner": {
                          "id": "0x226d833075c26dbf9aa377de0363e435808953a4"
                        }
                      }
                    ],
                    "id": "0x0d9d6d05a37353a98a9beaaf2c852089793f5dd1",
                    "balance": {
                      "wxHoprBalance": "0"
                    }
                  }
                },
                {
                  "owner": {
                    "id": "0x01bfbcb6a2924b083969ce6237adbbf3bfa7de13"
                  },
                  "safe": {
                    "registeredNodesInNetworkRegistry": [
                      {
                        "node": {
                          "id": "0xdc233cdf1e22d3da9c9de06b0b3ab1f590ec1658"
                        }
                      }
                    ],
                    "owners": [
                      {
                        "owner": {
                          "id": "0x01bfbcb6a2924b083969ce6237adbbf3bfa7de13"
                        }
                      }
                    ],
                    "id": "0x32d61c49d22aeb55986a190f8c4a85ab2a6878aa",
                    "balance": {
                      "wxHoprBalance": "0"
                    }
                  }
                },
                {
                  "owner": {
                    "id": "0x01bfbcb6a2924b083969ce6237adbbf3bfa7de13"
                  },
                  "safe": {
                    "registeredNodesInNetworkRegistry": [
                      {
                        "node": {
                          "id": "0x3dbac01674c21adcbbfe3103f59cabb5a1995abf"
                        }
                      }
                    ],
                    "owners": [
                      {
                        "owner": {
                          "id": "0x01bfbcb6a2924b083969ce6237adbbf3bfa7de13"
                        }
                      }
                    ],
                    "id": "0x4c4adf3436cc46a9d9ec05345a197611b2c1b0f8",
                    "balance": {
                      "wxHoprBalance": "0"
                    }
                  }
                },
                {
                  "owner": {
                    "id": "0x226d833075c26dbf9aa377de0363e435808953a4"
                  },
                  "safe": {
                    "registeredNodesInNetworkRegistry": [
                      {
                        "node": {
                          "id": "0x9c2a518b2a444578be8bb9da3409ddeec83f16f1"
                        }
                      }
                    ],
                    "owners": [
                      {
                        "owner": {
                          "id": "0x226d833075c26dbf9aa377de0363e435808953a4"
                        }
                      }
                    ],
                    "id": "0x55a4818df25173d3e73b33230f31de480a127740",
                    "balance": {
                      "wxHoprBalance": "0"
                    }
                  }
                },
                {
                  "owner": {
                    "id": "0x01bfbcb6a2924b083969ce6237adbbf3bfa7de13"
                  },
                  "safe": {
                    "registeredNodesInNetworkRegistry": [
                      {
                        "node": {
                          "id": "0x9674a156a8b15af0063e016363b2691a616e37e3"
                        }
                      }
                    ],
                    "owners": [
                      {
                        "owner": {
                          "id": "0x01bfbcb6a2924b083969ce6237adbbf3bfa7de13"
                        }
                      }
                    ],
                    "id": "0x5aceba9374fbc12aa9d7557f8e536de4d059fdc3",
                    "balance": {
                      "wxHoprBalance": "0"
                    }
                  }
                },
                {
                  "owner": {
                    "id": "0x226d833075c26dbf9aa377de0363e435808953a4"
                  },
                  "safe": {
                    "registeredNodesInNetworkRegistry": [
                      {
                        "node": {
                          "id": "0xb874626ff6717c37c925a90052cf7963c5405aeb"
                        }
                      }
                    ],
                    "owners": [
                      {
                        "owner": {
                          "id": "0x226d833075c26dbf9aa377de0363e435808953a4"
                        }
                      }
                    ],
                    "id": "0x5e777f25ab693469deb7085d9e82a8793490e054",
                    "balance": {
                      "wxHoprBalance": "0"
                    }
                  }
                },
                {
                  "owner": {
                    "id": "0x226d833075c26dbf9aa377de0363e435808953a4"
                  },
                  "safe": {
                    "registeredNodesInNetworkRegistry": [
                      {
                        "node": {
                          "id": "0x22ac1e1e16d37008b30e07739204fb8b63d050d1"
                        }
                      }
                    ],
                    "owners": [
                      {
                        "owner": {
                          "id": "0x226d833075c26dbf9aa377de0363e435808953a4"
                        }
                      }
                    ],
                    "id": "0x61d04ce8b6eda6a4a420674f1a2fa79096de2eb2",
                    "balance": {
                      "wxHoprBalance": "1"
                    }
                  }
                },
                {
                  "owner": {
                    "id": "0x01bfbcb6a2924b083969ce6237adbbf3bfa7de13"
                  },
                  "safe": {
                    "registeredNodesInNetworkRegistry": [
                      {
                        "node": {
                          "id": "0x2ec274d3e3957be7d45a6539021b8937c1f69299"
                        }
                      }
                    ],
                    "owners": [
                      {
                        "owner": {
                          "id": "0x01bfbcb6a2924b083969ce6237adbbf3bfa7de13"
                        }
                      }
                    ],
                    "id": "0x643a7122664ef14bde14ff0ed3c86a487ab5dffd",
                    "balance": {
                      "wxHoprBalance": "0"
                    }
                  }
                },
                {
                  "owner": {
                    "id": "0x226d833075c26dbf9aa377de0363e435808953a4"
                  },
                  "safe": {
                    "registeredNodesInNetworkRegistry": [
                      {
                        "node": {
                          "id": "0x037bebadd20b11816c0dbf5ee4905addbbac932f"
                        }
                      },
                      {
                        "node": {
                          "id": "0x098c33a07281bfbb9010b22ea16e0500789fc6c3"
                        }
                      },
                      {
                        "node": {
                          "id": "0xc440419850680e4f9ad8089b011915b24bdc0759"
                        }
                      }
                    ],
                    "owners": [
                      {
                        "owner": {
                          "id": "0x226d833075c26dbf9aa377de0363e435808953a4"
                        }
                      },
                      {
                        "owner": {
                          "id": "0x84aa5bbccfc1a77e99e81d45d4ffa2c1f5f7dea2"
                        }
                      }
                    ],
                    "id": "0x989b9a0c195a7b416794070dfbc5dc8c1bcfb6d6",
                    "balance": {
                      "wxHoprBalance": "413311.33"
                    }
                  }
                },
                {
                  "owner": {
                    "id": "0x226d833075c26dbf9aa377de0363e435808953a4"
                  },
                  "safe": {
                    "registeredNodesInNetworkRegistry": [
                      {
                        "node": {
                          "id": "0xaf695285f8ac0ec525ed0742056511b65de55b44"
                        }
                      }
                    ],
                    "owners": [
                      {
                        "owner": {
                          "id": "0x226d833075c26dbf9aa377de0363e435808953a4"
                        }
                      }
                    ],
                    "id": "0x9d94201f47ec5ac919c78fb93d296fd55a6413f3",
                    "balance": {
                      "wxHoprBalance": "30346.87"
                    }
                  }
                },
                {
                  "owner": {
                    "id": "0x226d833075c26dbf9aa377de0363e435808953a4"
                  },
                  "safe": {
                    "registeredNodesInNetworkRegistry": [],
                    "owners": [
                      {
                        "owner": {
                          "id": "0x226d833075c26dbf9aa377de0363e435808953a4"
                        }
                      }
                    ],
                    "id": "0xa3ce5fbe37c29eb544c8daf9fc5869bfe40b3a66",
                    "balance": {
                      "wxHoprBalance": "0"
                    }
                  }
                },
                {
                  "owner": {
                    "id": "0x226d833075c26dbf9aa377de0363e435808953a4"
                  },
                  "safe": {
                    "registeredNodesInNetworkRegistry": [],
                    "owners": [
                      {
                        "owner": {
                          "id": "0x226d833075c26dbf9aa377de0363e435808953a4"
                        }
                      }
                    ],
                    "id": "0xb06eb2ee7a0e85ee11962359b69754d72290ccc8",
                    "balance": {
                      "wxHoprBalance": "0"
                    }
                  }
                },
                {
                  "owner": {
                    "id": "0x01bfbcb6a2924b083969ce6237adbbf3bfa7de13"
                  },
                  "safe": {
                    "registeredNodesInNetworkRegistry": [
                      {
                        "node": {
                          "id": "0x58c97e9594a7f04afd99c19ecb72576f9700e74a"
                        }
                      }
                    ],
                    "owners": [
                      {
                        "owner": {
                          "id": "0x01bfbcb6a2924b083969ce6237adbbf3bfa7de13"
                        }
                      }
                    ],
                    "id": "0xb9a2b35ba73e57fc802787750ffbcf13dc2ad33d",
                    "balance": {
                      "wxHoprBalance": "0"
                    }
                  }
                },
                {
                  "owner": {
                    "id": "0x01bfbcb6a2924b083969ce6237adbbf3bfa7de13"
                  },
                  "safe": {
                    "registeredNodesInNetworkRegistry": [
                      {
                        "node": {
                          "id": "0xf5a5f2f9ef402064673d2a65afba4dcb4b3e4e43"
                        }
                      }
                    ],
                    "owners": [
                      {
                        "owner": {
                          "id": "0x01bfbcb6a2924b083969ce6237adbbf3bfa7de13"
                        }
                      }
                    ],
                    "id": "0xbf52e7a45b005790c0fb8fbf2a6cdf122211ce11",
                    "balance": {
                      "wxHoprBalance": "0"
                    }
                  }
                },
                {
                  "owner": {
                    "id": "0x01bfbcb6a2924b083969ce6237adbbf3bfa7de13"
                  },
                  "safe": {
                    "registeredNodesInNetworkRegistry": [
                      {
                        "node": {
                          "id": "0x6982f884c593745918cd08be39b4761cd6cf5acb"
                        }
                      }
                    ],
                    "owners": [
                      {
                        "owner": {
                          "id": "0x01bfbcb6a2924b083969ce6237adbbf3bfa7de13"
                        }
                      }
                    ],
                    "id": "0xcc1fe3d659a9028fff13141f9bf84321f6fb59f1",
                    "balance": {
                      "wxHoprBalance": "0"
                    }
                  }
                },
                {
                  "owner": {
                    "id": "0x226d833075c26dbf9aa377de0363e435808953a4"
                  },
                  "safe": {
                    "registeredNodesInNetworkRegistry": [
                      {
                        "node": {
                          "id": "0xb816eefe4558b19e09331f3d7626e50ace74cfbd"
                        }
                      }
                    ],
                    "owners": [
                      {
                        "owner": {
                          "id": "0x226d833075c26dbf9aa377de0363e435808953a4"
                        }
                      }
                    ],
                    "id": "0xd61818bc09de5f8496468b36436dc729800dacd0",
                    "balance": {
                      "wxHoprBalance": "30311.93"
                    }
                  }
                }
              ]
            }
        }))
        .unwrap();

        let mut asset_list = AssetList::default();
        asset_list.from_response(body).unwrap();
        debug!("{:?}", asset_list);

        assert_eq!(asset_list.asset_list.len(), 2);
        assert_eq!(
            asset_list
                .asset_list
                .get(&address!("226d833075c26dbf9aa377de0363e435808953a4"))
                .unwrap()
                .balance
                .last()
                .unwrap(),
            &U256::from_str("30311930000000000000000").unwrap()
        );
    }
}
