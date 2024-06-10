# Distribution Script

This command-line application, written in Rust, verifies signed Gnosis validator data and checks if the signer is eligible for the [500 GNO distribution](https://twitter.com/GnosisDAO/status/1783874344013463583) by GnosisDAO as a result of [GIP-98](https://forum.gnosis.io/t/gip-98-should-gnosisdao-invest-in-hopr-to-kickstart-development-of-gnosisvpn/8348).

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
    -d, --deposit-data-dir <DEPOSIT_DATA_DIR>
                    Directory where all the deposit data files are stored
    -c, --claim-history-path <CLAIM_HISTORY_PATH>
                    The path to the claim history
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
There are two identical signed deposit datas under the `./test` folder. Check if they are eligible if the minimum requirement is to have at least 20 HOPR tokens in a Safe and 1 running HOPR node:
```shell
$ cargo run -- --deposit-data-dir ./test --hopr-amount 20 --min-nodes 1 --claim-history-path ./test/claim_history.csv > result.log
```

