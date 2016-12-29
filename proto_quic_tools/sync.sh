#!/bin/bash

if [ "$PROTO_QUIC_ROOT" == "" ]; then
    echo "PROTO_QUIC_ROOT is not set"
    exit 1
fi

echo "_____ running src/third_party/binutils/download.py"
$PROTO_QUIC_ROOT/third_party/binutils/download.py
echo "_____ running /usr/bin/python src/build/linux/sysroot_scripts/install-sysroot.py --running-as-hook"
/usr/bin/python $PROTO_QUIC_ROOT/build/linux/sysroot_scripts/install-sysroot.py --running-as-hook
