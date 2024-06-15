use alloy_primitives::Address;
use clap::{Parser, ValueHint};
use log::{debug, error, info};
use requirements::{check_owners_eligibility, Claims};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};
use subgraph::{AssetList, SubgraphQuery};
use validators::{DepositData, SignedDepositData};

pub mod errors;
pub mod requirements;
pub mod subgraph;
pub mod validators;

/// Command line arguments
#[derive(Debug, Clone, Parser)]
#[command(author, version, about, long_about = None)]
pub struct CliArgs {
    /// Directory to all the signed deposit data files
    #[clap(
        help = "Directory to where all the input signed deposit data files are stored",
        long,
        short,
        value_hint = ValueHint::DirPath,
    )]
    pub input_signed_data_dir: String,

    /// Directory to the final deposit data file
    #[clap(
        help = "Directory to where the final output deposit data file is stored",
        long,
        short,
        value_hint = ValueHint::DirPath,
    )]
    pub output_deposit_data_dir: String,

    /// Path to store claim history
    #[clap(
        short,
        long,
        help = "The path to the claim history",
        value_hint = ValueHint::FilePath,
        name = "claim_history_path"
    )]
    pub claim_history_path: PathBuf,

    /// Minimum amount of HOPR tokens in a Safe
    #[clap(
        help = "Hopr amount in ether, e.g. 10000000",
        long,
        short = 't',
        default_value = "10000000"
    )]
    hopr_amount: String,

    /// Minimum number of nodes in a Safe
    #[clap(
        help = "Minimum number of nodes in a Safe",
        long,
        short,
        default_value = "1"
    )]
    min_nodes: u32,

    /// Subgraph query snapshot block number
    #[clap(
        help = "Snapshot block number for the subgraph query",
        long,
        short,
        default_value = "34310645"
    )]
    block_number: u32,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args = CliArgs::parse();

    // Read files from the directory
    let directory = fs::read_dir(Path::new(&args.input_signed_data_dir))?;
    let files = directory
        .filter_map(|file| {
            let file = file.ok()?;
            let path = file.path();
            if path.is_file() && path.extension()?.to_str()? == "json" {
                Some(path)
            } else {
                None
            }
        })
        .collect::<Vec<PathBuf>>();
    info!("To Read files: {:?}", files);

    // Verify the signature of the deposit data
    let mut validator_addresses: Vec<Address> = vec![];
    let mut read_deposit_data: HashMap<Address, DepositData> = Default::default();
    for file in files {
        info!("Reading deposit data file: {:?}", &file);
        let result =
            SignedDepositData::read_from_file(file.clone()).and_then(|signed_deposit_data| {
                signed_deposit_data
                    .validate_and_verify_data()
                    .map(|deposit_data| {
                        info!("Signature verified for {:?}", &file);
                        validator_addresses.push(signed_deposit_data.address);
                        // only store the string data, if all the signatures and deposit_data are valid
                        read_deposit_data.insert(signed_deposit_data.address, deposit_data);
                    })
            });

        if let Err(e) = result {
            error!("Error processing file: {:?}", e);
            debug!("Skipping file: {:?}", &file);
        }
    }
    info!("Verified {:?} owner addresses", &validator_addresses.len());

    // Check the requirements
    let requirements = requirements::Requirements::new(args.hopr_amount.parse()?, args.min_nodes);

    // Read the subgraph
    let subgraph_query = SubgraphQuery::new(args.block_number.into(), &validator_addresses);
    let response = subgraph_query.run().await?;
    debug!("{:?}", response);
    let mut asset_list = AssetList::default();
    asset_list.from_response(response)?;

    // Read claimed history
    let mut claim_history = Claims::read_from_csv(&args.claim_history_path)?;

    // Check owners eligibility
    let eligible_owners = check_owners_eligibility(
        &validator_addresses,
        &requirements?,
        &asset_list,
        &mut claim_history,
    );

    println!("Eligible owners: {:?}", eligible_owners);

    // Write the claimed history
    info!("Writing claim history to {:?}", &args.claim_history_path);
    claim_history.write_to_csv(&args.claim_history_path)?;

    // Get all the eligible deposit data into one array
    debug!("Get all the elibile deposit data into one array");
    let mut eligible_deposit_data: Vec<DepositData> = vec![];
    for owner in eligible_owners {
        if let Some(deposit_data) = read_deposit_data.get(&owner) {
            eligible_deposit_data.push(deposit_data.clone());
        } else {
            error!("Signer and message not found in deposit data")
        }
    }

    debug!("Write the eligible deposit data to one single json file");
    // Write the eligible deposit_data array to one single json file
    let eligible_deposit_data_file =
        Path::new(&args.output_deposit_data_dir).join("eligible_deposit_data.json");
    fs::write(
        eligible_deposit_data_file,
        serde_json::to_string(&eligible_deposit_data)?,
    )?;

    Ok(())
}
