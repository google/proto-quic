#!/usr/bin/env python
#
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import argparse
import os
import shutil
import sys
import tempfile

from util import build_utils


_SRC_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                         '..', '..', '..'))
_RETROLAMBDA_JAR_PATH = os.path.normpath(os.path.join(
    _SRC_ROOT, 'third_party', 'retrolambda', 'retrolambda-2.3.0.jar'))


def _OnStaleMd5(input_jar, output_jar, classpath, android_sdk_jar):
  with build_utils.TempDir() as temp_dir:
    build_utils.ExtractAll(input_jar, path=temp_dir)
    cmd = [
        'java',
        '-Dretrolambda.inputDir=' + temp_dir,
        '-Dretrolambda.classpath=' +
            ':'.join([temp_dir] + classpath + [android_sdk_jar]),
        '-javaagent:' + _RETROLAMBDA_JAR_PATH,
        '-jar',
        _RETROLAMBDA_JAR_PATH,
    ]

    build_utils.CheckOutput(cmd, print_stdout=False)
    build_utils.ZipDir(output_jar + '.tmp', temp_dir)
    shutil.move(output_jar + '.tmp', output_jar)


def main():
  args = build_utils.ExpandFileArgs(sys.argv[1:])
  parser = argparse.ArgumentParser()
  build_utils.AddDepfileOption(parser)
  parser.add_argument('--input-jar', required=True,
                      help='Jar input path to include .class files from.')
  parser.add_argument('--output-jar', required=True,
                      help='Jar output path.')
  parser.add_argument('--classpath', required=True,
                      help='Classpath.')
  parser.add_argument('--android-sdk-jar', required=True,
                      help='Android sdk jar path.')
  options = parser.parse_args(args)

  options.classpath = build_utils.ParseGnList(options.classpath)
  input_paths = options.classpath + [options.input_jar]
  output_paths = [options.output_jar]

  build_utils.CallAndWriteDepfileIfStale(
      lambda: _OnStaleMd5(options.input_jar, options.output_jar,
                          options.classpath, options.android_sdk_jar),
      options,
      input_paths=input_paths,
      input_strings=[],
      output_paths=output_paths)


if __name__ == '__main__':
  sys.exit(main())
