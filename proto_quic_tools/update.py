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

import fileinput
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
                 'base',
                 'build_overrides',
                 'buildtools',
                 'net/quic/core',
                 'net/quic/test_tools',
                 'net/third_party/mozilla_security_manager',
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
                 'sdch',
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

def clean_build_file(file_to_remove, filename):
  if not filename.endswith("gyp") and not filename.endswith("gypi") and not filename.endswith("gn") and not filename.endswith("gni"):
    return
  print "   removing " + file_to_remove + " from " + filename
  for line in fileinput.input(filename, inplace=True):
    if file_to_remove not in line:
      print line.rstrip('\n')

def copy_each_file(directory):
  for filename in os.listdir(libquic_root + "/" + directory):
    if os.path.isfile(libquic_root + "/" + directory + "/" + filename):
      if filename.endswith("gyp") or filename.endswith("gypi") or filename.endswith("run_all_unittests.cc") or filename.endswith("gn") or filename.endswith("gni"):
        print "skipping build file ", directory + "/" + filename
      else:
        libquic_file = libquic_root + "/" + directory + "/" + filename
        chrome_file = chrome_root + "/" + directory + "/" + filename
        if os.path.isfile(chrome_file):
          if verbose:
            print "copy ", libquic_file, " " , chrome_file
          shutil.copyfile(chrome_file, libquic_file)
        else:
          print "removing ", libquic_file
          gyp_dir = directory.split("/")[0];
          try:
            command = "grep -r " + filename + " " + libquic_root + "/" + gyp_dir + "/*"
            files_to_clean = subprocess.check_output(command, shell=True)
            for file_to_clean in files_to_clean.split("\n"):
              if file_to_clean:
                clean_build_file(filename, file_to_clean.split(":")[0]);
          except subprocess.CalledProcessError, e:
            print "  found no references to " + filename + " in " + gyp_dir + "/";
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
