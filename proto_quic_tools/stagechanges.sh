#!/bin/bash

if [ "$PROTO_QUIC_ROOT" == "" ]; then
    echo "PROTO_QUIC_ROOT is not set"
    exit 1
fi

if [ ! -d "$PROTO_QUIC_ROOT" ]; then
    echo "$PROTO_QUIC_ROOT directory does not exist."
    exit 1
fi

cd $PROTO_QUIC_ROOT
../proto_quic_tools/cleanup.sh

echo "copying working copies of build files"
cp $PROTO_QUIC_ROOT/BUILD.gn $PROTO_QUIC_ROOT/../modified_files/BUILD.gn
cp $PROTO_QUIC_ROOT/net/test/run_all_unittests.cc \
   $PROTO_QUIC_ROOT/../modified_files/net/test/run_all_unittests.cc
cp $PROTO_QUIC_ROOT/url/BUILD.gn $PROTO_QUIC_ROOT/../modified_files/url/BUILD.gn

echo "staging changes to upload"
git add .
git add ../modified_files
git add ../proto_quic_tools
git add ../CONTRIBUTING.md
git add ../README.md
