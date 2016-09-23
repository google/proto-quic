#!/usr/bin/python
# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import shutil
import subprocess
import sys
import tempfile


def rel_to_abs(rel_path):
  script_path = os.path.dirname(os.path.abspath(__file__))
  return os.path.join(script_path, rel_path)


java_bin_path = os.getenv('JAVA_HOME', '')
if java_bin_path:
  java_bin_path = os.path.join(java_bin_path, 'bin')

main_class = 'org.chromium.closure.compiler.Runner'
jar_name = 'runner.jar'
src_dir = 'src'
closure_jar_relpath = os.path.join('..', 'compiler', 'compiler.jar')
src_path = rel_to_abs(src_dir)


def run_and_communicate(command, error_template):
  print >> sys.stderr, command
  proc = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
  proc.communicate()
  if proc.returncode:
    print >> sys.stderr, error_template % proc.returncode
    sys.exit(proc.returncode)


def build_artifacts():
  print 'Compiling...'
  java_files = []
  for root, dirs, files in sorted(os.walk(src_path)):
    for file_name in files:
      java_files.append(os.path.join(root, file_name))

  bin_path = tempfile.mkdtemp()
  manifest_file = tempfile.NamedTemporaryFile(mode='wt', delete=False)
  try:
    manifest_file.write('Class-Path: %s\n' % closure_jar_relpath)
    manifest_file.close()
    javac_path = os.path.join(java_bin_path, 'javac')
    javac_command = '%s -d %s -cp %s %s' % (
        javac_path, bin_path, rel_to_abs(closure_jar_relpath),
        ' '.join(java_files))
    run_and_communicate(javac_command, 'Error: javac returned %d')

    print 'Building jar...'
    artifact_path = rel_to_abs(jar_name)
    jar_path = os.path.join(java_bin_path, 'jar')
    jar_command = '%s cvfme %s %s %s -C %s .' % (
        jar_path, artifact_path, manifest_file.name, main_class, bin_path)
    run_and_communicate(jar_command, 'Error: jar returned %d')
  finally:
    os.remove(manifest_file.name)
    shutil.rmtree(bin_path, True)

  print 'Done.'


def show_usage_and_die():
  print 'usage: %s' % os.path.basename(__file__)
  print 'Builds runner.jar from the %s directory contents' % src_dir
  sys.exit(1)


def main():
  if len(sys.argv) > 1:
    show_usage_and_die()

  build_artifacts()


if __name__ == '__main__':
  main()
