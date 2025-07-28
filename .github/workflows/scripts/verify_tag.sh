#!/usr/bin/env bash
set -e

err() {
    echo -e "\e[31m\e[1merror:\e[0m $@" 1>&2;
}

status() {
    local width=12
    printf "\e[32m\e[1m%${width}s\e[0m %s\n" "$1" "$2"
}

get_toml_version () {
    local toml_path="$1"

    local manifest="Cargo.toml"
    echo $(dasel -f $manifest $toml_path | tr -d '"')
}

check_version () {
    local ref=$1
    local toml_path=$2

    # strip preceeding 'v' if it exists on tag
    ref=${ref/#v}

    local toml_version=$(get_toml_version "$toml_path")
  
    if [ "$toml_version" != "$ref" ]; then
        err "Crate version $toml_version for $toml_path, doesn't match tag version $ref"
        exit 1
    else
      status "Crate version for $toml_path matches tag $toml_version"
    fi
}

REF=$1

if [ -z "$REF" ]; then
    err "Expected ref to be set"
    exit 1
fi

for toml_path in \
    "package.version" \
; do
    check_version $REF $toml_path
done