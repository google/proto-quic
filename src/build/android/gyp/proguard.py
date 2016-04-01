#!/usr/bin/env python
#
# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import optparse
import os
import sys

from util import build_utils
from util import proguard_util


def _ParseOptions(args):
  parser = optparse.OptionParser()
  build_utils.AddDepfileOption(parser)
  parser.add_option('--proguard-path',
                    help='Path to the proguard executable.')
  parser.add_option('--input-paths',
                    help='Paths to the .jar files proguard should run on.')
  parser.add_option('--output-path', help='Path to the generated .jar file.')
  parser.add_option('--proguard-configs',
                    help='Paths to proguard configuration files.')
  parser.add_option('--mapping', help='Path to proguard mapping to apply.')
  parser.add_option('--is-test', action='store_true',
      help='If true, extra proguard options for instrumentation tests will be '
      'added.')
  parser.add_option('--tested-apk-info', help='Path to the proguard .info file '
      'for the tested apk')
  parser.add_option('--classpath', action='append',
                    help='Classpath for proguard.')
  parser.add_option('--stamp', help='Path to touch on success.')
  parser.add_option('--verbose', '-v', action='store_true',
                    help='Print all proguard output')

  options, _ = parser.parse_args(args)

  classpath = []
  for arg in options.classpath:
    classpath += build_utils.ParseGypList(arg)
  options.classpath = classpath

  return options


def main(args):
  args = build_utils.ExpandFileArgs(args)
  options = _ParseOptions(args)

  proguard = proguard_util.ProguardCmdBuilder(options.proguard_path)
  proguard.injars(build_utils.ParseGypList(options.input_paths))
  proguard.configs(build_utils.ParseGypList(options.proguard_configs))
  proguard.outjar(options.output_path)

  if options.mapping:
    proguard.mapping(options.mapping)

  if options.tested_apk_info:
    proguard.tested_apk_info(options.tested_apk_info)

  classpath = list(set(options.classpath))
  proguard.libraryjars(classpath)
  proguard.verbose(options.verbose)

  input_paths = proguard.GetInputs()

  build_utils.CallAndWriteDepfileIfStale(
      proguard.CheckOutput,
      options,
      input_paths=input_paths,
      input_strings=proguard.build(),
      output_paths=[options.output_path])


if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))
