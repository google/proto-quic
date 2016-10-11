#!/bin/bash

if [ "$PROTO_QUIC_ROOT" == "" ]; then
    echo "PROTO_QUIC_ROOT is not set"
    exit 1
fi

echo "removing unwanted files"
cd $PROTO_QUIC_ROOT
rm -rf build/linux/*sysroot
rm -rf third_party/boringssl/src/fuzz/client_corpus
rm -rf third_party/boringssl/src/fuzz/server_corpus
rm -rf out
find -name .git -exec rm -rf {} \;  # don't remove .git file in parent!
cd ..
find -name *.pyc -exec rm -rf {} \;
find -name *~ -exec rm -rf {} \;

echo "copying working copies of build files"
cp $PROTO_QUIC_ROOT/BUILD.gn $PROTO_QUIC_ROOT/../modified_files/BUILD.gn
cp $PROTO_QUIC_ROOT/net/BUILD.gn \
   $PROTO_QUIC_ROOT/../modified_files/net/BUILD.gn
cp $PROTO_QUIC_ROOT/net/net.gypi $PROTO_QUIC_ROOT/../modified_files/net/net.gypi
cp $PROTO_QUIC_ROOT/net/test/run_all_unittests.cc \
   $PROTO_QUIC_ROOT/../modified_files/net/test/run_all_unittests.cc
cp $PROTO_QUIC_ROOT/build/config/sysroot.gni \
   $PROTO_QUIC_ROOT/../modified_files//build/config/sysroot.gni
cp $PROTO_QUIC_ROOT/url/BUILD.gn $PROTO_QUIC_ROOT/../modified_files/url/BUILD.gn

echo "staging changes to upload"
cd $PROTO_QUIC_ROOT
git add .
git add ../modified_files
git add ../proto_quic_tools
git add ../CONTRIBUTING
git add ../README.md
cd -
