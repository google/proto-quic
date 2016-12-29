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

usage = "export CHROME_ROOT=/path/to/chrome/src;export PROTO_QUIC_ROOT=/path/to/proto-quic; update.py"
chrome_root = os.environ.get('CHROME_ROOT')
proto_quic_root = os.environ.get('PROTO_QUIC_ROOT')
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


# Merges net/net.gypi. Copies any new additions to net.gypi but leaves
# them commented out in the proto_quic repo. If any of these files are
# needed for proto_quic, they will have to be uncommented in the new
# net.gypi.
def merge_net_gypi():
  old_net_gypi = open(proto_quic_root + "/../modified_files/net/net.gypi", 'r')
  new_net_gypi = open(chrome_root + "/net/net.gypi", 'r')
  accept_lines = []

  for line in old_net_gypi:
    line = line.strip()
    if line and line[0] != "#":
      accept_lines.append(line)
  old_net_gypi.close()

  # Write empty lines, comments, and unmodified lines as they are.
  # Add newly introduced lines into the proto_quic version, but
  # comment them out.
  merged_net_gypi = open(proto_quic_root + "/../modified_files/net/net.gypi", 'w')
  for line in new_net_gypi:
    stripped = line.strip()
    if not stripped or stripped[0] == "#" or stripped in accept_lines:
      merged_net_gypi.write(line)
    else:
      merged_net_gypi.write("#" + line)

  new_net_gypi.close()
  merged_net_gypi.close()


# Copies modified build and other files into proto-quic.
def copy_modified_files():
  # Modified files
  command = "cp -r " + modified_files_dir + "/* " + proto_quic_root
  print "running", command;
  os.system(command)
  # .gn file at root of tree
  command = "cp " + chrome_root + "/.gn " + proto_quic_root
  print "running", command;
  os.system(command)
  # New version file
  command = "cp " + chrome_root + "/chrome/VERSION " + proto_quic_root + "/chrome/VERSION"
  print "running", command;
  os.system(command)


# Since proto-quic users do not use gclient sync, runs necessary parts of it.
def sync():
  command = "/" + proto_quic_root + "proto_quic_tools/sync.sh"
  print "running", command;
  os.system(command)

def cleanup():
  command = "/" + proto_quic_root + "proto_quic_tools/cleanup.sh"
  print "running", command;
  os.system(command)


copy_directories()
merge_net_gypi()
copy_modified_files()
cleanup()
sync()
