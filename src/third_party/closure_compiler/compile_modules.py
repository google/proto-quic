#!/usr/bin/env python
# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import argparse
from checker import Checker as Checker
import os
import sys

try:
  import json
except:
  import simplejson as json


class Module(object):
  def __init__(self, name, sources, depends=[], externs=[]):
    self.name = name
    self.sources = sources
    # TODO(dbeam): support depending on other modules/dependency flattening.
    self.depends = depends
    self.externs = externs

  @staticmethod
  def from_dict(d):
    keys = d.keys()

    required = ["name", "sources"]
    assert all(r in keys for r in required), "Module missing name or sources"

    allowed = required + ["depends", "externs"]
    assert all(k in allowed for k in keys), "Module has unknown key"

    depends = d["depends"] if "depends" in d else []
    externs = d["externs"] if "externs" in d else []
    return Module(d["name"], d["sources"], depends=depends, externs=externs)


# TODO(dbeam): should ModuleParser be internal to ModuleCompiler or should we
# pass Modules into ModuleCompiler.compile()? Maybe this is fine?
class ModuleParser(object):
  _cache = {}

  def __init__(self, verbose=False):
    self._verbose = verbose

  def parse(self, file_path):
    if file_path in self._cache:
      print "(INFO) Found module file %s in the cache" % file_path
      return self._cache[file_path]

    file = open(file_path, "r")
    data = json.load(file)
    file.close()

    if self._verbose:
      pretty_json = json.dumps(data, indent=2, separators=(',', ': ')).strip()
      print "(INFO) Layout: " + os.linesep + pretty_json + os.linesep

    self._cache[file_path] = [Module.from_dict(m) for m in data]
    return self._cache[file_path]


class ModuleCompiler(object):
  _checker = None
  _parser = None

  def __init__(self, verbose=False):
    self._verbose = verbose

  def _debug(self, msg, prefix="(INFO) ", suffix=""):
    if self._verbose:
      print prefix + msg.strip() + suffix

  def compile(self, module_file):
    self._debug("MODULE FILE: " + module_file, prefix="")

    # NOTE: It's possible but unlikely that |_checker| or |_parser|'s verbosity
    # isn't the same as |self._verbose| due to this class being called with
    # verbose=False then verbose=True in the same program.
    self._parser = self._parser or ModuleParser(verbose=self._verbose)
    self._checker = self._checker or Checker(verbose=self._verbose)

    current_dir = os.getcwd()
    module_dir = os.path.dirname(module_file)
    rel_path = lambda f: f

    if current_dir and module_dir:
      here_to_module_dir = os.path.relpath(module_dir, current_dir)
      if here_to_module_dir:
        rel_path = lambda f: os.path.join(here_to_module_dir, f)

    modules = self._parser.parse(module_file)

    for m in modules:
      self._debug("MODULE: " + m.name, prefix="", suffix=os.linesep)

      for s in m.sources:
        depends = [rel_path(d) for d in m.depends]
        externs = [rel_path(e) for e in m.externs]
        exit_code, _ = self._checker.check(rel_path(s), depends=depends,
                                           externs=externs)
        if exit_code:
          sys.exit(exit_code)

        if s != m.sources[-1]:
          self._debug(os.linesep, prefix="")

      if m != modules[-1]:
        self._debug(os.linesep, prefix="")


def main(opts):
  module_compiler = ModuleCompiler(verbose=opts.verbose)
  for module_file in opts.module_file:
    module_compiler.compile(module_file)


if __name__ == "__main__":
  parser = argparse.ArgumentParser(
      description="Typecheck JavaScript using Closure compiler")
  parser.add_argument("-v", "--verbose", action="store_true",
                      help="Show more information as this script runs")
  parser.add_argument("module_file", nargs=argparse.ONE_OR_MORE,
                      help="Path to a modules file to check")
  main(parser.parse_args())
