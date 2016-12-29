#!/bin/bash

if [ "$PROTO_QUIC_ROOT" == "" ]; then
    echo "PROTO_QUIC_ROOT is not set."
    exit 1
fi

if [ ! -d "$PROTO_QUIC_ROOT" ]; then
    echo "$PROTO_QUIC_ROOT directory does not exist."
    exit 1
fi

echo "removing unwanted files"
cd $PROTO_QUIC_ROOT
rm -rf build/linux/*sysroot
rm -rf third_party/boringssl/src/fuzz/client_corpus
rm -rf third_party/boringssl/src/fuzz/server_corpus
rm -rf third_party/boringssl/src/fuzz/cert_corpus
rm -rf out
find -name .git -exec rm -rf {} \;  # don't remove .git file in parent!
cd ..
find -name *.pyc -exec rm -rf {} \;
find -name *~ -exec rm -rf {} \;
