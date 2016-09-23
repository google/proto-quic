# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import fnmatch
import imp
import logging
import optparse
import os
import sys
import zipfile

from telemetry import benchmark
from telemetry.core import discover
from telemetry.internal.util import command_line
from telemetry.internal.util import path
from telemetry.internal.util import path_set

try:
  from modulegraph import modulegraph  # pylint: disable=import-error
except ImportError as err:
  modulegraph = None
  import_error = err

from core import bootstrap
from core import path_util

DEPS_FILE = 'bootstrap_deps'


def FindBootstrapDependencies(base_dir):
  deps_file = os.path.join(base_dir, DEPS_FILE)
  if not os.path.exists(deps_file):
    return []
  deps_paths = bootstrap.ListAllDepsPaths(deps_file)
  return set(os.path.realpath(os.path.join(
      path_util.GetChromiumSrcDir(), '..', deps_path))
             for deps_path in deps_paths)


def FindPythonDependencies(module_path):
  logging.info('Finding Python dependencies of %s', module_path)
  if modulegraph is None:
    raise import_error

  sys_path = sys.path
  sys.path = list(sys_path)
  try:
    # Load the module to inherit its sys.path modifications.
    sys.path.insert(0, os.path.abspath(os.path.dirname(module_path)))
    imp.load_source(
        os.path.splitext(os.path.basename(module_path))[0], module_path)

    # Analyze the module for its imports.
    graph = modulegraph.ModuleGraph()
    graph.run_script(module_path)

    # Filter for only imports in Chromium.
    for node in graph.nodes():
      if not node.filename:
        continue
      module_path = os.path.realpath(node.filename)

      _, incoming_edges = graph.get_edges(node)
      message = 'Discovered %s (Imported by: %s)' % (
          node.filename, ', '.join(
              d.filename for d in incoming_edges
              if d is not None and d.filename is not None))
      logging.info(message)

      # This check is done after the logging/printing above to make sure that
      # we also print out the dependency edges that include python packages
      # that are not in chromium.
      if not path.IsSubpath(module_path, path_util.GetChromiumSrcDir()):
        continue

      yield module_path
      if node.packagepath is not None:
        for p in node.packagepath:
          yield p

  finally:
    sys.path = sys_path


def FindPageSetDependencies(base_dir):
  logging.info('Finding page sets in %s', base_dir)

  # Add base_dir to path so our imports relative to base_dir will work.
  sys.path.append(base_dir)
  tests = discover.DiscoverClasses(base_dir, base_dir, benchmark.Benchmark,
                                   index_by_class_name=True)

  for test_class in tests.itervalues():
    test_obj = test_class()

    # Ensure the test's default options are set if needed.
    parser = optparse.OptionParser()
    test_obj.AddCommandLineArgs(parser, None)
    options = optparse.Values()
    for k, v in parser.get_default_values().__dict__.iteritems():
      options.ensure_value(k, v)

    # Page set paths are relative to their runner script, not relative to us.
    path.GetBaseDir = lambda: base_dir
    # TODO: Loading the page set will automatically download its Cloud Storage
    # deps. This is really expensive, and we don't want to do this by default.
    story_set = test_obj.CreateStorySet(options)

    # Add all of its serving_dirs as dependencies.
    for serving_dir in story_set.serving_dirs:
      yield serving_dir


def FindExcludedFiles(files, options):
  # Define some filters for files.
  def IsHidden(path_string):
    for pathname_component in path_string.split(os.sep):
      if pathname_component.startswith('.'):
        return True
    return False

  def IsPyc(path_string):
    return os.path.splitext(path_string)[1] == '.pyc'

  def IsInCloudStorage(path_string):
    return os.path.exists(path_string + '.sha1')

  def MatchesExcludeOptions(path_string):
    for pattern in options.exclude:
      if (fnmatch.fnmatch(path_string, pattern) or
          fnmatch.fnmatch(os.path.basename(path_string), pattern)):
        return True
    return False

  # Collect filters we're going to use to exclude files.
  exclude_conditions = [
      IsHidden,
      IsPyc,
      IsInCloudStorage,
      MatchesExcludeOptions,
  ]

  # Check all the files against the filters.
  for file_path in files:
    if any(condition(file_path) for condition in exclude_conditions):
      yield file_path


def FindDependencies(target_paths, options):
  # Verify arguments.
  for target_path in target_paths:
    if not os.path.exists(target_path):
      raise ValueError('Path does not exist: %s' % target_path)

  dependencies = path_set.PathSet()

  # Including Telemetry's major entry points will (hopefully) include Telemetry
  # and all its dependencies. If the user doesn't pass any arguments, we just
  # have Telemetry.
  dependencies |= FindPythonDependencies(os.path.realpath(
      os.path.join(path_util.GetTelemetryDir(),
                   'telemetry', 'benchmark_runner.py')))
  dependencies |= FindPythonDependencies(os.path.realpath(
      os.path.join(path_util.GetTelemetryDir(),
                   'telemetry', 'testing', 'run_tests.py')))

  # Add dependencies.
  for target_path in target_paths:
    base_dir = os.path.dirname(os.path.realpath(target_path))

    dependencies.add(base_dir)
    dependencies |= FindBootstrapDependencies(base_dir)
    dependencies |= FindPythonDependencies(target_path)
    if options.include_page_set_data:
      dependencies |= FindPageSetDependencies(base_dir)

  # Remove excluded files.
  dependencies -= FindExcludedFiles(set(dependencies), options)

  return dependencies


def ZipDependencies(target_paths, dependencies, options):
  base_dir = os.path.dirname(os.path.realpath(path_util.GetChromiumSrcDir()))

  with zipfile.ZipFile(options.zip, 'w', zipfile.ZIP_DEFLATED) as zip_file:
    # Add dependencies to archive.
    for dependency_path in dependencies:
      path_in_archive = os.path.join(
          'telemetry', os.path.relpath(dependency_path, base_dir))
      zip_file.write(dependency_path, path_in_archive)

    # Add symlinks to executable paths, for ease of use.
    for target_path in target_paths:
      link_info = zipfile.ZipInfo(
          os.path.join('telemetry', os.path.basename(target_path)))
      link_info.create_system = 3  # Unix attributes.
      # 010 is regular file, 0111 is the permission bits rwxrwxrwx.
      link_info.external_attr = 0100777 << 16  # Octal.

      relative_path = os.path.relpath(target_path, base_dir)
      link_script = (
          '#!/usr/bin/env python\n\n'
          'import os\n'
          'import sys\n\n\n'
          'script = os.path.join(os.path.dirname(__file__), \'%s\')\n'
          'os.execv(sys.executable, [sys.executable, script] + sys.argv[1:])'
          % relative_path)

      zip_file.writestr(link_info, link_script)


class FindDependenciesCommand(command_line.OptparseCommand):
  """Prints all dependencies"""

  @classmethod
  def AddCommandLineArgs(cls, parser, _):
    parser.add_option(
        '-v', '--verbose', action='count', dest='verbosity',
        help='Increase verbosity level (repeat as needed).')

    parser.add_option(
        '-p', '--include-page-set-data', action='store_true', default=False,
        help='Scan tests for page set data and include them.')

    parser.add_option(
        '-e', '--exclude', action='append', default=[],
        help='Exclude paths matching EXCLUDE. Can be used multiple times.')

    parser.add_option(
        '-z', '--zip',
        help='Store files in a zip archive at ZIP.')

  @classmethod
  def ProcessCommandLineArgs(cls, parser, args, _):
    if args.verbosity >= 2:
      logging.getLogger().setLevel(logging.DEBUG)
    elif args.verbosity:
      logging.getLogger().setLevel(logging.INFO)
    else:
      logging.getLogger().setLevel(logging.WARNING)

  def Run(self, args):
    target_paths = args.positional_args
    dependencies = FindDependencies(target_paths, args)
    if args.zip:
      ZipDependencies(target_paths, dependencies, args)
      print 'Zip archive written to %s.' % args.zip
    else:
      print '\n'.join(sorted(dependencies))
    return 0
