use alloy_primitives::Address;
use clap::{Parser, ValueHint};
use log::{debug, info};
use requirements::{check_owners_eligibility, Claims};
use std::{
    fs,
    path::{Path, PathBuf},
};
use subgraph::{AssetList, SubgraphQuery};
use validators::verify_deposit_data;

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
        help = "Directory to where all the deposit data files are stored",
        long,
        short,
        value_hint = ValueHint::DirPath,
    )]
    pub deposit_data_dir: String,

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
    let directory = fs::read_dir(Path::new(&args.deposit_data_dir))?;
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
    for file in files {
        info!("Verifying deposit data file: {:?}", &file);
        validator_addresses.push(verify_deposit_data(file)?);
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
    claim_history.write_to_csv(&args.claim_history_path)?;

    Ok(())
}
