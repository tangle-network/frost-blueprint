#!/bin/sh
set -e

function required_tool() {
    if ! command -v $1 &> /dev/null
    then
        echo "$1 could not be found"
        echo "hint: install $1 using $2"
        exit 1
    fi
}

required_tool subkey "cargo install -f subkey"
required_tool cargo-tangle "cargo install -f cargo-tangle"
required_tool jq "https://jqlang.github.io/jq/download/"

function insert_key() {
    if [ "$#" -ne 3 ]; then
        echo "Usage: insert_key <key> <scheme> <path>"
        exit 1
    fi
    echo "Inserting key $1 (Scheme: $2) into $3"
    # remove 0x prefix from seed
    seed=$(subkey inspect "$1" --scheme $2 --output-type json | jq -r '.secretSeed' | sed 's/^0x//')
    cargo tangle blueprint keygen -k $2 -s $seed -p $3
}

# Alice
insert_key "//Alice" "sr25519" "target/keystore/alice"
insert_key "//Alice" "ed25519" "target/keystore/alice"
insert_key "//Alice" "ecdsa" "target/keystore/alice"
# Bob
insert_key "//Bob" "sr25519" "target/keystore/bob"
insert_key "//Bob" "ed25519" "target/keystore/bob"
insert_key "//Bob" "ecdsa" "target/keystore/bob"
# Charlie
insert_key "//Charlie" "sr25519" "target/keystore/charlie"
insert_key "//Charlie" "ed25519" "target/keystore/charlie"
insert_key "//Charlie" "ecdsa" "target/keystore/charlie"
