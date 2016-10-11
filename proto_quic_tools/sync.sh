#!/bin/bash

echo "Installing build deps and syncing with Chromium repository... "
./src/build/install-build-deps.sh
./src/third_party/binutils/download.py
echo "... done."
