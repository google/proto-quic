#!/bin/bash

if [ "$PROTO_QUIC_ROOT" == "" ]; then
    echo "PROTO_QUIC_ROOT is not set"
    exit
fi

cd $PROTO_QUIC_ROOT
echo "removing unwanted files"
rm -rf build/linux/*sysroot
rm -rf third_party/boringssl/src/fuzz/client_corpus
rm -rf third_party/boringssl/src/fuzz/server_corpus
rm -rf out
find -name .git -exec rm -rf {} \;
find -name *.pyc -exec rm -rf {} \;
find -name *~ -exec rm -rf {} \;
echo "staging changes to upload"
git add .
git add ../modified_files
git add ../proto_quic_tools
git add ../CONTRIBUTING
git add ../README.md
cd -
