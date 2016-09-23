#!/usr/bin/python
# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import argparse
import ast
import collections
import os
import sys


sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import processor


def remove_duplicates_with_order(has_duplicates):
  return list(collections.OrderedDict.fromkeys(has_duplicates))


def expand_depends(source, dep):
  if ":" not in dep:
    return [dep], {}

  gyp_relative_path, target = dep.split(":")
  gyp_path = os.path.join(os.path.dirname(source), gyp_relative_path)
  gyp_content = ast.literal_eval(open(gyp_path).read())

  for target_description in gyp_content["targets"]:
    if target_description["target_name"] == target:
      break
  else:
    raise ValueError("Target '%s' not found in file '%s'" %
                     (target, gyp_path))

  depends = []
  externs = []
  if "variables" in target_description:
    depends = target_description["variables"].get("depends", [])
    externs = target_description["variables"].get("externs", [])

  def attach_gyp_dir(relative_path):
    return os.path.join(os.path.dirname(gyp_path), relative_path)

  target_source = attach_gyp_dir(target + ".js")
  expanded_depends, expanded_externs = resolve_recursive_dependencies(
      target_source,
      depends,
      externs)

  expanded_depends = map(attach_gyp_dir, expanded_depends)
  expanded_externs = set(map(attach_gyp_dir, expanded_externs))

  expanded_depends.append(target_source)

  return expanded_depends, expanded_externs


def resolve_recursive_dependencies(source, input_depends, depends_externs):
  output_depends = []
  output_externs = set(depends_externs)

  for depends in input_depends:
    expanded_depends, expanded_externs = expand_depends(source, depends)
    output_depends.extend(expanded_depends)
    output_externs.update(expanded_externs)

  output_depends = remove_duplicates_with_order(output_depends)

  return output_depends, output_externs


def GetInputs(args):
  parser = argparse.ArgumentParser()
  parser.add_argument("sources", nargs=argparse.ONE_OR_MORE)
  parser.add_argument("-d", "--depends", nargs=argparse.ZERO_OR_MORE,
                      default=[])
  parser.add_argument("-e", "--externs", nargs=argparse.ZERO_OR_MORE,
                      default=[])
  opts = parser.parse_args(args)

  # TODO(twellington): resolve dependencies for multiple sources.
  if len(opts.sources) == 1:
    depends, externs = resolve_recursive_dependencies(
        os.path.normpath(os.path.join(os.getcwd(), opts.sources[0])),
        opts.depends,
        opts.externs)
  else:
    depends = opts.depends
    externs = set(opts.externs)

  files = set()
  for file in set(opts.sources) | set(depends) | externs:
    files.add(file)
    files.update(processor.Processor(file).included_files)

  return files


if __name__ == "__main__":
  print "\n".join(GetInputs(sys.argv[1:]))
