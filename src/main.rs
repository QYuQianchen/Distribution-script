pub mod validators;
pub mod subgraph;
pub mod requirements;
pub mod errors;

use alloy_primitives::Address;
use log::info;
use validators::verify_deposit_data;
use std::{fs, path::{Path, PathBuf}};
use clap::{Parser, ValueHint};

#[derive(Debug, Clone, Parser)]
#[command(author, version, about, long_about = None)]
pub struct CliArgs {
    /// Directory to all the identity files
    #[clap(
        help = "Directory to where all the deposit data files are stored",
        long,
        short = 'd',
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

    
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>>{
    env_logger::init();

    let args = CliArgs::parse();

    // read files from the directory
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

    // verify the signature of the deposit data
    let mut validator_addresses: Vec<Address> = vec![];
    for file in files {
        info!("Verifing deposit data file: {:?}", &file);
        validator_addresses.push(verify_deposit_data(file)?);
    }
    info!("Verified {:?} addresses", &validator_addresses.len());


    Ok(())
}
