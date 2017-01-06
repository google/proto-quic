proto-quic
==========

proto-quic is intended as a standalone library for [QUIC](https://www.chromium.org/quic).

It contains the subset of Chromium code and dependencies required for QUIC so
folks can use the Chromium code without depending on all of Chromium.  It is
intended to be a cross-platform library, but will only support the set (or a
strict subset) of platforms which Chromium already supports.

This is *not* an officially supported Google product.  It's being kept up to
date (on a theoretical weekly basis) as a best-effort side-project by some of
the current QUIC developers. Worst case, should Google's priorities change about
supporting a standalone QUIC library, it's all open source and any interested
community can just clone the repo and continue updates on their own.

Currently, the only supported platform is Linux (and the only tested version is
Google's Ubuntu clone) but Windows and iOS should be coming soon.

Building on Linux
-----------------

0. Clone this repository:
   ```
   git clone https://github.com/google/proto-quic.git
   cd proto-quic
   export PROTO_QUIC_ROOT=`pwd`/src
   export PATH=$PATH:`pwd`/depot_tools
   ./proto_quic_tools/sync.sh
   ```

1. If you're building for the first time, install dependencies:
   ```
   ./src/build/install-build-deps.sh
   ```

2. Build the QUIC client, server, and tests:
   ```
   cd src
   gn gen out/Default && ninja -C out/Default quic_client quic_server net_unittests
   ```

From then on you can follow the usual Chromium instructions for playing with the
toy client and server:

https://www.chromium.org/quic/playing-with-quic
