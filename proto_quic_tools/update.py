#!/usr/bin/python

"""Script to update proto-quic from "upstream" chrome.

This script assumes CHROME_ROOT is set to /path/to/chrome/src and
PROTO_QUIC_ROOT is set to /path/to/proto-quic/src and will otherwise exit
immediately.

update.py will by default remove and re-copy all directories listed in
full_copy_directories and  attempt to merge changes in build files
from CHROME_ROOT
"""

import fileinput
import os
import shutil
import subprocess
import sys

usage = "export CHROME_ROOT=/path/to/chrome/src;export PROTO_QUIC_ROOT=/path/to/proto-quic/src; update.py"
chrome_root = os.environ.get('CHROME_ROOT')
proto_quic_root = os.environ.get('PROTO_QUIC_ROOT')
tools_dir = proto_quic_root + "/../proto_quic_tools"
modified_files_dir = proto_quic_root + "/../modified_files"
print "Running with chrome_root=", chrome_root, ", proto_quic_root=", proto_quic_root;
if chrome_root == None or proto_quic_root == None:
  sys.exit(usage)

full_copy_directories =[
                 'base',
                 'build',
                 'build_overrides',
                 'buildtools',
                 'crypto',
                 'net',
                 'testing',
                 'third_party/apple_apsl',
                 'third_party/binutils',
                 'third_party/boringssl',
                 'third_party/brotli',
                 'third_party/ced',
                 'third_party/closure_compiler',
                 'third_party/drmemory',
                 'third_party/googletest',
                 'third_party/icu',
                 'third_party/instrumented_libraries',
                 'third_party/libxml/',
                 'third_party/llvm-build',
                 'third_party/modp_b64',
                 'third_party/protobuf',
                 'third_party/pyftpdlib',
                 'third_party/pywebsocket',
                 'third_party/tcmalloc',
                 'third_party/tlslite',
                 'third_party/yasm',
                 'third_party/zlib',
                 'tools',
                 'sdch',
                 'url',
]

# Removes and copies full directories listed in full_copy_directories
def copy_directories():
  for directory in full_copy_directories:
    print "removing and copying ", directory
    shutil.rmtree(proto_quic_root + "/" + directory)
    shutil.copytree(chrome_root + "/" + directory, proto_quic_root + "/" + directory, symlinks=True)


# Copies modified build and other files into proto-quic.
def copy_modified_files():
  # Modified files
  command = "cp -r " + modified_files_dir + "/* " + proto_quic_root
  print "running", command;
  os.system(command)
  # New version file
  command = "cp " + chrome_root + "/chrome/VERSION " + proto_quic_root + "/chrome/VERSION"
  print "running", command;
  os.system(command)


# Since proto-quic users do not use gclient sync, runs necessary parts of it.
def sync():
  command = tools_dir + "/sync.sh"
  print "running", command
  os.system(command)

def cleanup():
  command = tools_dir + "/cleanup.sh"
  print "running", command
  os.system(command)


# In the functions called below, the sequence of copy, merge, copy, and cleanup attempts
# to leave the workspace in exactly the state that someone checking out repo will see.
copy_directories()
copy_modified_files()
cleanup()
# Finally sync pulls down files required for building which are not part of the repo.
sync()
