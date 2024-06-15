# Distribution Script

This command-line application, written in Rust, verifies signed Gnosis validator data and checks if the signer an active HOPR node runner.

This script uses `alloy-rs` for Ethereum primitives and `graphql_client` to query subgraphs. When querying subgraphs, it first attempts to query the production subgraph endpoint but falls back to the development endpoint in the Subgraph Studio.

## Development Installation
1. Install Rust using the [official guide](https://www.rust-lang.org/tools/install).
2. Build:
```shell
$ cargo build
```
3. Create a `.env` file according to the `.env.example` and fill it in with API keys.
4. Load environmental variables:
```shell
$ source .env
```
5. Run to see the `--help` message:
```shell
$ cargo run -- -h
```

## Usage
1. Production build:
```shell
$ cargo build --release
```

```shell
$ ./target/release/distribution_script --help
Usage: distribution_script [OPTIONS] --deposit-data-dir <DEPOSIT_DATA_DIR> --claim-history-path <CLAIM_HISTORY_PATH>

Options:
    -i, --input-signed-data-dir <INPUT_SIGNED_DATA_DIR>
            Directory to where all the input signed deposit data files are stored
    -o, --output-deposit-data-dir <OUTPUT_DEPOSIT_DATA_DIR>
            Directory to where the final output deposit data file is stored
    -t, --hopr-amount <HOPR_AMOUNT>
            HOPR amount in ether, e.g., 10000000 [default: 10000000]
    -m, --min-nodes <MIN_NODES>
            Minimum number of nodes in a Safe [default: 1]
    -b, --block-number <BLOCK_NUMBER>
            Snapshot block number for the subgraph query [default: 34310645]
    -h, --help
            Print help
    -V, --version
            Print version
```

## Example
There are two identical signed deposit datas under the `./test/input` folder. Check if they are eligible if the minimum requirement is to have at least 20 HOPR tokens in a Safe and 1 running HOPR node:
```shell
$ cargo run -- --input-signed-data-dir ./test/input -o ./test --hopr-amount 20 --min-nodes 1 --claim-history-path ./test/claim_history.csv > result.log
```
The command above should return an empty array as a result.

```shell
$ cargo run -- --input-signed-data-dir ./test/input -o ./test --hopr-amount 0 --min-nodes 0 --claim-history-path ./test/claim_history.csv > result.log
```