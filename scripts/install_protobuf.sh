#!/usr/bin/env bash
set -e

PROTOC_VERSION=$(cat ../PROTOC_VERSION)

check_protoc_version () {
    this_version=`protoc --version`
    return `[ "libprotoc $PROTOC_VERSION" = "$this_version" ]`
}

if check_protoc_version; then
    echo $PROTOC_VERSION detected.
    exit
fi

wget https://github.com/google/protobuf/archive/v$PROTOC_VERSION.tar.gz
tar -xzvf v$PROTOC_VERSION.tar.gz
cd protobuf-$PROTOC_VERSION && ./autogen.sh && ./configure --prefix=$HOME/protobuf && make && make install
