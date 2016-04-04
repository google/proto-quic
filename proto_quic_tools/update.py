#!/usr/bin/python

"""Script to update proto-quic from "upstream" chrome.

This script assumes CHROME_ROOT is set to /path/to/chrome/src and
                    LIBQUIC_ROOT is set to /path/to/libquic/src
and will otherwise exit immediately.

update.py will by default remove and re-copy all directories listed in
          full_copy_directories and then go through every file in every other
          listed directory and update it from the file in CHROME_ROOT

update.py [directory or file] will copy a new file from CHROME_ROOT to
          LIBQUIC_ROOT
"""

import os
import shutil
import subprocess
import sys

verbose = False
usage = "export CHROME_ROOT=/path/to/chrome/src;export LIBQUIC_ROOT=/path/to/libquic; update.py [filename]"
chrome_root = os.environ.get('CHROME_ROOT')
libquic_root = os.environ.get('LIBQUIC_ROOT')
print "Running with chrome_root=", chrome_root, ", libquic_root=", libquic_root;
if chrome_root == None or libquic_root == None:
  sys.exit(usage)

full_copy_directories =[
                 'base/allocator',
                 'base/third_party/nspr',
                 'base/third_party/dmg_fp',
                 'base/third_party/symbolize',
                 'base/third_party/valgrind',
                 'base/third_party/xdg_user_dirs',
                 'base/third_party/dynamic_annotations',
                 'base/third_party/libevent',
                 'base/third_party/superfasthash',
                 'base/third_party/icu',
                 'base/trace_event',
                 'crypto/third_party/nss',
                 'net/quic/congestion_control/',
                 'net/quic/test_tools/',
                 'net/third_party/mozilla_security_manager',
                 'third_party/apple_apsl',
                 'third_party/binutils',
                 'third_party/boringssl',
                 'third_party/brotli',
                 'third_party/icu',
                 'third_party/instrumented_libraries',
                 'third_party/libxml/',
                 'third_party/modp_b64',
                 'third_party/protobuf',
                 'third_party/tcmalloc',
                 'third_party/yasm',
                 'third_party/zlib',
                 'sdch/open-vcdiff',
                 'url/third_party/mozilla',
]

def full_copy(name):
  for directory in full_copy_directories:
    if name.startswith(directory):
      return True
  return False


def directory_to_skip(name):
  if name.startswith("tools") or name.startswith("build") or not name or name.startswith("out"):
    return True
  return False

def copy_each_file(directory):
  for filename in os.listdir(libquic_root + "/" + directory):
    if os.path.isfile(libquic_root + "/" + directory + "/" + filename):
      if filename.endswith("gyp") or filename.endswith("gypi") or filename.endswith("run_all_unittests.cc"):
        print "skipping build file ", directory + "/" + filename
      else:
        libquic_file = libquic_root + "/" + directory + "/" + filename
        chrome_file = chrome_root + "/" + directory + "/" + filename
        if os.path.isfile(chrome_file):
          if verbose:
            print "copy ", libquic_file, " " , chrome_file
          shutil.copyfile(chrome_file, libquic_file)
        else:
          print "remove ", libquic_file
          os.remove(libquic_file)

def copy_directories():
  for directory in full_copy_directories:
    print "removing and copying ", directory
    shutil.rmtree(libquic_root + "/" + directory)
    shutil.copytree(chrome_root + "/" + directory, libquic_root + "/" + directory, symlinks=True)

def copy_all():
  copy_directories()
  for item in os.walk(libquic_root):
    directory_name = item[0][len(libquic_root)+1:]
    if full_copy(directory_name):
      if verbose:
        print "should do a full copy of '", directory_name, "'"
    elif directory_to_skip(directory_name):
      if verbose:
        print "skipping directory '", directory_name, "'"
    else:
      absolute_path = libquic_root + "/" + directory_name
      if verbose:
        print "per file copy of '", directory_name , "'"
      copy_each_file(directory_name)

def copy_file():
  filename = sys.argv[1];
  command = "cp -r " + chrome_root + "/" + filename + " " + libquic_root + "/" + filename
  print "running", command;
  os.system(command)

if len(sys.argv) > 1:
  copy_file()
else:
  copy_all()


