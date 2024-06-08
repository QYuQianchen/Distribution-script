use std::{
    fmt::{Debug, Formatter},
    env
};
use graphql_client::{GraphQLQuery, Response};
use alloy_primitives::Address;
use log::{debug, info};
use reqwest;
use crate::errors::SubgraphError;

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

#[derive(Debug, Clone)]
pub struct Assets {
    pub balance: BigDecimal,
    pub safes: Vec<Address>,
    pub nodes: Vec<Address>,
    pub linked_owners: Vec<Address>,
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


#[cfg(test)]
pub mod tests {
    use super::*;
    use log::debug;

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
}