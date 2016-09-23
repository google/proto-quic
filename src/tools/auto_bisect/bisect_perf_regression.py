#!/usr/bin/env python
# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Chromium auto-bisect tool

This script bisects a range of commits using binary search. It starts by getting
reference values for the specified "good" and "bad" commits. Then, for revisions
in between, it will get builds, run tests and classify intermediate revisions as
"good" or "bad" until an adjacent "good" and "bad" revision is found; this is
the culprit.

If the culprit is a roll of a depedency repository (e.g. v8), it will then
expand the revision range and continue the bisect until a culprit revision in
the dependency repository is found.

Example usage using git commit hashes, bisecting a performance test based on
the mean value of a particular metric:

./tools/auto_bisect/bisect_perf_regression.py
  --command "out/Release/performance_ui_tests \
      --gtest_filter=ShutdownTest.SimpleUserQuit"\
  --metric shutdown/simple-user-quit
  --good_revision 1f6e67861535121c5c819c16a666f2436c207e7b\
  --bad-revision b732f23b4f81c382db0b23b9035f3dadc7d925bb\

Example usage using git commit positions, bisecting a functional test based on
whether it passes or fails.

./tools/auto_bisect/bisect_perf_regression.py\
  --command "out/Release/content_unittests -single-process-tests \
            --gtest_filter=GpuMemoryBufferImplTests"\
  --good_revision 408222\
  --bad_revision 408232\
  --bisect_mode return_code\
  --builder_type full

In practice, the auto-bisect tool is usually run on tryserver.chromium.perf
try bots, and is started by tools/run-bisect-perf-regression.py using
config parameters from tools/auto_bisect/bisect.cfg.
"""

import argparse
import copy
import errno
import hashlib
import json
import logging
import os
import re
import shlex
import shutil
import StringIO
import sys
import time
import urllib
import urllib2

sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..',
                             'third_party', 'catapult', 'telemetry'))

from bisect_printer import BisectPrinter
from bisect_results import BisectResults
import bisect_results_json
from bisect_state import BisectState
import bisect_utils
import builder
import fetch_build
import math_utils
import query_crbug
import request_build
import source_control

# The script is in chromium/src/tools/auto_bisect. Throughout this script,
# we use paths to other things in the chromium/src repository.

# Possible return values from BisectPerformanceMetrics.RunTest.
BUILD_RESULT_SUCCEED = 0
BUILD_RESULT_FAIL = 1
BUILD_RESULT_SKIPPED = 2

# How many times to repeat the test on the last known good and first known bad
# revisions in order to assess a more accurate confidence score in the
# regression culprit.
BORDER_REVISIONS_EXTRA_RUNS = 2

# Patch template to add a new file, DEPS.sha under src folder.
# This file contains SHA1 value of the DEPS changes made while bisecting
# dependency repositories. This patch send along with DEPS patch to try server.
# When a build requested is posted with a patch, bisect builders on try server,
# once build is produced, it reads SHA value from this file and appends it
# to build archive filename.
DEPS_SHA_PATCH = """diff --git DEPS.sha DEPS.sha
new file mode 100644
--- /dev/null
+++ DEPS.sha
@@ -0,0 +1 @@
+%(deps_sha)s
"""

REGRESSION_NOT_REPRODUCED_MESSAGE_TEMPLATE = """
Bisect did not clearly reproduce a regression between the given "good"
and "bad" revisions.

Results:
"Good" revision: {good_rev}
\tMean: {good_mean}
\tStandard error: {good_std_err}
\tSample size: {good_sample_size}

"Bad" revision: {bad_rev}
\tMean: {bad_mean}
\tStandard error: {bad_std_err}
\tSample size: {bad_sample_size}

You may want to try bisecting on a different platform or metric.
"""

# Git branch name used to run bisect try jobs.
BISECT_TRYJOB_BRANCH = 'bisect-tryjob'
# Git master branch name.
BISECT_MASTER_BRANCH = 'master'
# File to store 'git diff' content.
BISECT_PATCH_FILE = 'deps_patch.txt'
# SVN repo where the bisect try jobs are submitted.
PERF_SVN_REPO_URL = 'svn://svn.chromium.org/chrome-try/try-perf'
FULL_SVN_REPO_URL = 'svn://svn.chromium.org/chrome-try/try'
ANDROID_CHROME_SVN_REPO_URL = ('svn://svn.chromium.org/chrome-try-internal/'
                               'try-perf')
PERF_DASH_RESULTS_URL = 'https://chromeperf.appspot.com/post_bisect_results'


class RunGitError(Exception):

  def __str__(self):
    return '%s\nError executing git command.' % self.args[0]


def GetSHA1HexDigest(contents):
  """Returns SHA1 hex digest of the given string."""
  return hashlib.sha1(contents).hexdigest()


def WriteStringToFile(text, file_name):
  """Writes text to a file, raising an RuntimeError on failure."""
  try:
    with open(file_name, 'wb') as f:
      f.write(text)
  except IOError:
    raise RuntimeError('Error writing to file [%s]' % file_name)


def ReadStringFromFile(file_name):
  """Writes text to a file, raising an RuntimeError on failure."""
  try:
    with open(file_name) as f:
      return f.read()
  except IOError:
    raise RuntimeError('Error reading file [%s]' % file_name)


def ChangeBackslashToSlashInPatch(diff_text):
  """Formats file paths in the given patch text to Unix-style paths."""
  if not diff_text:
    return None
  diff_lines = diff_text.split('\n')
  for i in range(len(diff_lines)):
    line = diff_lines[i]
    if line.startswith('--- ') or line.startswith('+++ '):
      diff_lines[i] = line.replace('\\', '/')
  return '\n'.join(diff_lines)


def _ParseRevisionsFromDEPSFileManually(deps_file_contents):
  """Parses the vars section of the DEPS file using regular expressions.

  Args:
    deps_file_contents: The DEPS file contents as a string.

  Returns:
    A dictionary in the format {depot: revision} if successful, otherwise None.
  """
  # We'll parse the "vars" section of the DEPS file.
  rxp = re.compile('vars = {(?P<vars_body>[^}]+)', re.MULTILINE)
  re_results = rxp.search(deps_file_contents)

  if not re_results:
    return None

  # We should be left with a series of entries in the vars component of
  # the DEPS file with the following format:
  # 'depot_name': 'revision',
  vars_body = re_results.group('vars_body')
  rxp = re.compile(r"'(?P<depot_body>[\w_-]+)':[\s]+'(?P<rev_body>[\w@]+)'",
                   re.MULTILINE)
  re_results = rxp.findall(vars_body)

  return dict(re_results)


def _WaitUntilBuildIsReady(fetch_build_func, builder_name, build_request_id,
                           max_timeout, buildbot_server_url):
  """Waits until build is produced by bisect builder on try server.

  Args:
    fetch_build_func: Function to check and download build from cloud storage.
    builder_name: Builder bot name on try server.
    build_request_id: A unique ID of the build request posted to try server.
    max_timeout: Maximum time to wait for the build.
    buildbot_server_url: Buildbot url to check build status.

  Returns:
     Downloaded archive file path if exists, otherwise None.
  """
  # Build number on the try server.
  build_num = None
  # Interval to check build on cloud storage.
  poll_interval = 60
  # Interval to check build status on try server in seconds.
  status_check_interval = 600
  last_status_check = time.time()
  start_time = time.time()

  while True:
    # Checks for build on gs://chrome-perf and download if exists.
    res = fetch_build_func()
    if res:
      return (res, 'Build successfully found')
    elapsed_status_check = time.time() - last_status_check
    # To avoid overloading try server with status check requests, we check
    # build status for every 10 minutes.
    if elapsed_status_check > status_check_interval:
      last_status_check = time.time()
      if not build_num:
        # Get the build number on try server for the current build.
        build_num = request_build.GetBuildNumFromBuilder(
            build_request_id, builder_name, buildbot_server_url)
      # Check the status of build using the build number.
      # Note: Build is treated as PENDING if build number is not found
      # on the the try server.
      build_status, status_link = request_build.GetBuildStatus(
          build_num, builder_name, buildbot_server_url)
      if build_status == request_build.FAILED:
        return (None, 'Failed to produce build, log: %s' % status_link)
    elapsed_time = time.time() - start_time
    if elapsed_time > max_timeout:
      return (None, 'Timed out: %ss without build' % max_timeout)

    logging.info('Time elapsed: %ss without build.', elapsed_time)
    time.sleep(poll_interval)
    # For some reason, mac bisect bots were not flushing stdout periodically.
    # As a result buildbot command is timed-out. Flush stdout on all platforms
    # while waiting for build.
    sys.stdout.flush()


def _UpdateV8Branch(deps_content):
  """Updates V8 branch in DEPS file to process v8_bleeding_edge.

  Check for "v8_branch" in DEPS file if exists update its value
  with v8_bleeding_edge branch. Note: "v8_branch" is added to DEPS
  variable from DEPS revision 254916, therefore check for "src/v8":
  <v8 source path> in DEPS in order to support prior DEPS revisions
  and update it.

  Args:
    deps_content: DEPS file contents to be modified.

  Returns:
    Modified DEPS file contents as a string.
  """
  new_branch = r'branches/bleeding_edge'
  v8_branch_pattern = re.compile(r'(?<="v8_branch": ")(.*)(?=")')
  if re.search(v8_branch_pattern, deps_content):
    deps_content = re.sub(v8_branch_pattern, new_branch, deps_content)
  else:
    # Replaces the branch assigned to "src/v8" key in DEPS file.
    # Format of "src/v8" in DEPS:
    # "src/v8":
    #    (Var("googlecode_url") % "v8") + "/trunk@" + Var("v8_revision"),
    # So, "/trunk@" is replace with "/branches/bleeding_edge@"
    v8_src_pattern = re.compile(
        r'(?<="v8"\) \+ "/)(.*)(?=@" \+ Var\("v8_revision"\))', re.MULTILINE)
    if re.search(v8_src_pattern, deps_content):
      deps_content = re.sub(v8_src_pattern, new_branch, deps_content)
  return deps_content


def _UpdateDEPSForAngle(revision, depot, deps_file):
  """Updates DEPS file with new revision for Angle repository.

  This is a hack for Angle depot case because, in DEPS file "vars" dictionary
  variable contains "angle_revision" key that holds git hash instead of
  SVN revision.

  And sometimes "angle_revision" key is not specified in "vars" variable,
  in such cases check "deps" dictionary variable that matches
  angle.git@[a-fA-F0-9]{40}$ and replace git hash.
  """
  deps_var = bisect_utils.DEPOT_DEPS_NAME[depot]['deps_var']
  try:
    deps_contents = ReadStringFromFile(deps_file)
    # Check whether the depot and revision pattern in DEPS file vars variable
    # e.g. "angle_revision": "fa63e947cb3eccf463648d21a05d5002c9b8adfa".
    angle_rev_pattern = re.compile(r'(?<="%s": ")([a-fA-F0-9]{40})(?=")' %
                                   deps_var, re.MULTILINE)
    match = re.search(angle_rev_pattern, deps_contents)
    if match:
      # Update the revision information for the given depot
      new_data = re.sub(angle_rev_pattern, revision, deps_contents)
    else:
      # Check whether the depot and revision pattern in DEPS file deps
      # variable. e.g.,
      # "src/third_party/angle": Var("chromium_git") +
      # "/angle/angle.git@fa63e947cb3eccf463648d21a05d5002c9b8adfa",.
      angle_rev_pattern = re.compile(
          r'(?<=angle\.git@)([a-fA-F0-9]{40})(?=")', re.MULTILINE)
      match = re.search(angle_rev_pattern, deps_contents)
      if not match:
        logging.info('Could not find angle revision information in DEPS file.')
        return False
      new_data = re.sub(angle_rev_pattern, revision, deps_contents)
    # Write changes to DEPS file
    WriteStringToFile(new_data, deps_file)
    return True
  except IOError, e:
    logging.warn('Something went wrong while updating DEPS file, %s', e)
  return False


def _TryParseHistogramValuesFromOutput(metric, text):
  """Attempts to parse a metric in the format HISTOGRAM <graph: <trace>.

  Args:
    metric: The metric as a list of [<trace>, <value>] strings.
    text: The text to parse the metric values from.

  Returns:
    A list of floating point numbers found, [] if none were found.
  """
  metric_formatted = 'HISTOGRAM %s: %s= ' % (metric[0], metric[1])

  text_lines = text.split('\n')
  values_list = []

  for current_line in text_lines:
    if metric_formatted in current_line:
      current_line = current_line[len(metric_formatted):]

      try:
        histogram_values = eval(current_line)

        for b in histogram_values['buckets']:
          average_for_bucket = float(b['high'] + b['low']) * 0.5
          # Extends the list with N-elements with the average for that bucket.
          values_list.extend([average_for_bucket] * b['count'])
      except Exception:
        pass

  return values_list


def _TryParseResultValuesFromOutput(metric, text):
  """Attempts to parse a metric in the format RESULT <graph>: <trace>= ...

  Args:
    metric: The metric as a list of [<trace>, <value>] string pairs.
    text: The text to parse the metric values from.

  Returns:
    A list of floating point numbers found.
  """
  # Format is: RESULT <graph>: <trace>= <value> <units>
  metric_re = re.escape('RESULT %s: %s=' % (metric[0], metric[1]))

  # The log will be parsed looking for format:
  # <*>RESULT <graph_name>: <trace_name>= <value>
  single_result_re = re.compile(
      metric_re + r'\s*(?P<VALUE>[-]?\d*(\.\d*)?)')

  # The log will be parsed looking for format:
  # <*>RESULT <graph_name>: <trace_name>= [<value>,value,value,...]
  multi_results_re = re.compile(
      metric_re + r'\s*\[\s*(?P<VALUES>[-]?[\d\., ]+)\s*\]')

  # The log will be parsed looking for format:
  # <*>RESULT <graph_name>: <trace_name>= {<mean>, <std deviation>}
  mean_stddev_re = re.compile(
      metric_re +
      r'\s*\{\s*(?P<MEAN>[-]?\d*(\.\d*)?),\s*(?P<STDDEV>\d+(\.\d*)?)\s*\}')

  text_lines = text.split('\n')
  values_list = []
  for current_line in text_lines:
    # Parse the output from the performance test for the metric we're
    # interested in.
    single_result_match = single_result_re.search(current_line)
    multi_results_match = multi_results_re.search(current_line)
    mean_stddev_match = mean_stddev_re.search(current_line)
    if (not single_result_match is None and
        single_result_match.group('VALUE')):
      values_list += [single_result_match.group('VALUE')]
    elif (not multi_results_match is None and
          multi_results_match.group('VALUES')):
      metric_values = multi_results_match.group('VALUES')
      values_list += metric_values.split(',')
    elif (not mean_stddev_match is None and
          mean_stddev_match.group('MEAN')):
      values_list += [mean_stddev_match.group('MEAN')]

  values_list = [float(v) for v in values_list
                 if bisect_utils.IsStringFloat(v)]

  return values_list


def _ParseMetricValuesFromOutput(metric, text):
  """Parses output from performance_ui_tests and retrieves the results for
  a given metric.

  Args:
    metric: The metric as a list of [<trace>, <value>] strings.
    text: The text to parse the metric values from.

  Returns:
    A list of floating point numbers found.
  """
  metric_values = _TryParseResultValuesFromOutput(metric, text)

  if not metric_values:
    metric_values = _TryParseHistogramValuesFromOutput(metric, text)

  return metric_values


def _GenerateProfileIfNecessary(command_args):
  """Checks the command line of the performance test for dependencies on
  profile generation, and runs tools/perf/generate_profile as necessary.

  Args:
    command_args: Command line being passed to performance test, as a list.

  Returns:
    False if profile generation was necessary and failed, otherwise True.
  """
  if '--profile-dir' in ' '.join(command_args):
    # If we were using python 2.7+, we could just use the argparse
    # module's parse_known_args to grab --profile-dir. Since some of the
    # bots still run 2.6, have to grab the arguments manually.
    arg_dict = {}
    args_to_parse = ['--profile-dir', '--browser']

    for arg_to_parse in args_to_parse:
      for i, current_arg in enumerate(command_args):
        if arg_to_parse in current_arg:
          current_arg_split = current_arg.split('=')

          # Check 2 cases, --arg=<val> and --arg <val>
          if len(current_arg_split) == 2:
            arg_dict[arg_to_parse] = current_arg_split[1]
          elif i + 1 < len(command_args):
            arg_dict[arg_to_parse] = command_args[i+1]

    path_to_generate = os.path.join('tools', 'perf', 'generate_profile')

    if '--profile-dir' in arg_dict and '--browser' in arg_dict:
      profile_path, profile_type = os.path.split(arg_dict['--profile-dir'])
      return not bisect_utils.RunProcess(
          [
              'python', path_to_generate,
              '--profile-type-to-generate', profile_type,
              '--browser', arg_dict['--browser'],
              '--output-dir', profile_path
          ])
    return False
  return True


def _IsRegressionReproduced(known_good_result, known_bad_result,
                            required_initial_confidence):
  """Checks whether the regression was reproduced based on the initial values.

  Args:
    known_good_result: A dict with the keys "values", "mean" and "std_err".
    known_bad_result: Same as above.
    required_initial_confidence: Minimum confidence score for the given
        good and bad revisions to avoid early aborting.

  Returns:
    True if there is a clear change between the result values for the given
    good and bad revisions, False otherwise.
  """
  def PossiblyFlatten(values):
    """Flattens if needed, by averaging the values in each nested list."""
    if isinstance(values, list) and all(isinstance(x, list) for x in values):
      return map(math_utils.Mean, values)
    return values

  initial_confidence = BisectResults.ConfidenceScore(
      PossiblyFlatten(known_bad_result['values']),
      PossiblyFlatten(known_good_result['values']),
      accept_single_bad_or_good=True)

  return initial_confidence >= required_initial_confidence


def _RegressionNotReproducedWarningMessage(
    good_revision, bad_revision, known_good_value, known_bad_value):
  return REGRESSION_NOT_REPRODUCED_MESSAGE_TEMPLATE.format(
      good_rev=good_revision,
      good_mean=known_good_value['mean'],
      good_std_err=known_good_value['std_err'],
      good_sample_size=len(known_good_value['values']),
      bad_rev=bad_revision,
      bad_mean=known_bad_value['mean'],
      bad_std_err=known_bad_value['std_err'],
      bad_sample_size=len(known_bad_value['values']))


class DepotDirectoryRegistry(object):

  def __init__(self, src_cwd):
    self.depot_cwd = {}
    for depot in bisect_utils.DEPOT_NAMES:
      # The working directory of each depot is just the path to the depot, but
      # since we're already in 'src', we can skip that part.
      path_in_src = bisect_utils.DEPOT_DEPS_NAME[depot]['src'][4:]
      self.SetDepotDir(depot, os.path.join(src_cwd, path_in_src))

    self.SetDepotDir('chromium', src_cwd)

  def SetDepotDir(self, depot_name, depot_dir):
    self.depot_cwd[depot_name] = depot_dir

  def GetDepotDir(self, depot_name):
    if depot_name in self.depot_cwd:
      return self.depot_cwd[depot_name]
    else:
      assert False, ('Unknown depot [ %s ] encountered. Possibly a new one '
                     'was added without proper support?' % depot_name)

  def ChangeToDepotDir(self, depot_name):
    """Given a depot, changes to the appropriate working directory.

    Args:
      depot_name: The name of the depot (see DEPOT_NAMES).
    """
    os.chdir(self.GetDepotDir(depot_name))


def _PrepareBisectBranch(parent_branch, new_branch):
  """Creates a new branch to submit bisect try job.

  Args:
    parent_branch: Parent branch to be used to create new branch.
    new_branch: New branch name.
  """
  current_branch, returncode = bisect_utils.RunGit(
      ['rev-parse', '--abbrev-ref', 'HEAD'])
  if returncode:
    raise RunGitError('Must be in a git repository to send changes to trybots.')

  current_branch = current_branch.strip()
  # Make sure current branch is master.
  if current_branch != parent_branch:
    output, returncode = bisect_utils.RunGit(['checkout', '-f', parent_branch])
    if returncode:
      raise RunGitError('Failed to checkout branch: %s.' % output)

  # Delete new branch if exists.
  output, returncode = bisect_utils.RunGit(['branch', '--list'])
  if new_branch in output:
    output, returncode = bisect_utils.RunGit(['branch', '-D', new_branch])
    if returncode:
      raise RunGitError('Deleting branch failed, %s', output)

  # Check if the tree is dirty: make sure the index is up to date and then
  # run diff-index.
  bisect_utils.RunGit(['update-index', '--refresh', '-q'])
  output, returncode = bisect_utils.RunGit(['diff-index', 'HEAD'])
  if output:
    raise RunGitError('Cannot send a try job with a dirty tree.')

  # Create and check out the telemetry-tryjob branch, and edit the configs
  # for the try job there.
  output, returncode = bisect_utils.RunGit(['checkout', '-b', new_branch])
  if returncode:
    raise RunGitError('Failed to checkout branch: %s.' % output)

  output, returncode = bisect_utils.RunGit(
      ['branch', '--set-upstream-to', parent_branch])
  if returncode:
    raise RunGitError('Error in git branch --set-upstream-to')


def _StartBuilderTryJob(
    builder_type, git_revision, builder_name, job_name, patch=None):
  """Attempts to run a try job from the current directory.

  Args:
    builder_type: One of the builder types in fetch_build, e.g. "perf".
    git_revision: A git commit hash.
    builder_name: Name of the bisect bot to be used for try job.
    bisect_job_name: Try job name, used to identify which bisect
        job was responsible for requesting a build.
    patch: A DEPS patch (used while bisecting dependency repositories),
        or None if we're bisecting the top-level repository.
  """
  # TODO(prasadv, qyearsley): Make this a method of BuildArchive
  # (which may be renamed to BuilderTryBot or Builder).
  try:
    # Temporary branch for running a try job.
    _PrepareBisectBranch(BISECT_MASTER_BRANCH, BISECT_TRYJOB_BRANCH)
    patch_content = '/dev/null'
    # Create a temporary patch file.
    if patch:
      WriteStringToFile(patch, BISECT_PATCH_FILE)
      patch_content = BISECT_PATCH_FILE

    try_command = [
        'try',
        '--bot=%s' % builder_name,
        '--revision=%s' % git_revision,
        '--name=%s' % job_name,
        '--svn_repo=%s' % _TryJobSvnRepo(builder_type),
        '--diff=%s' % patch_content,
    ]
    # Execute try job to build revision.
    print try_command
    output, return_code = bisect_utils.RunGit(try_command)

    command_string = ' '.join(['git'] + try_command)
    if return_code:
      raise RunGitError('Could not execute try job: %s.\n'
                        'Error: %s' % (command_string, output))
    logging.info('Try job successfully submitted.\n TryJob Details: %s\n%s',
                 command_string, output)
  finally:
    # Delete patch file if exists.
    try:
      os.remove(BISECT_PATCH_FILE)
    except OSError as e:
      if e.errno != errno.ENOENT:
        raise
    # Checkout master branch and delete bisect-tryjob branch.
    bisect_utils.RunGit(['checkout', '-f', BISECT_MASTER_BRANCH])
    bisect_utils.RunGit(['branch', '-D', BISECT_TRYJOB_BRANCH])


def _TryJobSvnRepo(builder_type):
  """Returns an SVN repo to use for try jobs based on the builder type."""
  if builder_type == fetch_build.PERF_BUILDER:
    return PERF_SVN_REPO_URL
  if builder_type == fetch_build.FULL_BUILDER:
    return FULL_SVN_REPO_URL
  if builder_type == fetch_build.ANDROID_CHROME_PERF_BUILDER:
    return ANDROID_CHROME_SVN_REPO_URL
  raise NotImplementedError('Unknown builder type "%s".' % builder_type)


class BisectPerformanceMetrics(object):
  """This class contains functionality to perform a bisection of a range of
  revisions to narrow down where performance regressions may have occurred.

  The main entry-point is the Run method.
  """

  def __init__(self, opts, src_cwd):
    """Constructs a BisectPerformancesMetrics object.

    Args:
      opts: BisectOptions object containing parsed options.
      src_cwd: Root src/ directory of the test repository (inside bisect/ dir).
    """
    super(BisectPerformanceMetrics, self).__init__()

    self.opts = opts
    self.src_cwd = src_cwd
    self.depot_registry = DepotDirectoryRegistry(self.src_cwd)
    self.printer = BisectPrinter(self.opts, self.depot_registry)
    self.cleanup_commands = []
    self.warnings = []
    self.builder = builder.Builder.FromOpts(opts)

  def PerformCleanup(self):
    """Performs cleanup when script is finished."""
    os.chdir(self.src_cwd)
    for c in self.cleanup_commands:
      if c[0] == 'mv':
        shutil.move(c[1], c[2])
      else:
        assert False, 'Invalid cleanup command.'

  def GetRevisionList(self, depot, bad_revision, good_revision):
    """Retrieves a list of all the commits between the bad revision and
    last known good revision."""

    cwd = self.depot_registry.GetDepotDir(depot)
    return source_control.GetRevisionList(bad_revision, good_revision, cwd=cwd)

  def _ParseRevisionsFromDEPSFile(self, depot):
    """Parses the local DEPS file to determine blink/skia/v8 revisions which may
    be needed if the bisect recurses into those depots later.

    Args:
      depot: Name of depot being bisected.

    Returns:
      A dict in the format {depot:revision} if successful, otherwise None.
    """
    try:
      deps_data = {
          'Var': lambda _: deps_data["vars"][_],
          'From': lambda *args: None,
      }

      deps_file = bisect_utils.FILE_DEPS_GIT
      if not os.path.exists(deps_file):
        deps_file = bisect_utils.FILE_DEPS
      execfile(deps_file, {}, deps_data)
      deps_data = deps_data['deps']

      rxp = re.compile(".git@(?P<revision>[a-fA-F0-9]+)")
      results = {}
      for depot_name, depot_data in bisect_utils.DEPOT_DEPS_NAME.iteritems():
        if (depot_data.get('platform') and
            depot_data.get('platform') != os.name):
          continue

        if depot_data.get('recurse') and depot in depot_data.get('from'):
          depot_data_src = depot_data.get('src') or depot_data.get('src_old')
          src_dir = deps_data.get(depot_data_src)
          if src_dir:
            self.depot_registry.SetDepotDir(depot_name, os.path.join(
                self.src_cwd, depot_data_src[4:]))
            re_results = rxp.search(src_dir)
            if re_results:
              results[depot_name] = re_results.group('revision')
            else:
              warning_text = ('Could not parse revision for %s while bisecting '
                              '%s' % (depot_name, depot))
              if not warning_text in self.warnings:
                self.warnings.append(warning_text)
          else:
            results[depot_name] = None
      return results
    except ImportError:
      deps_file_contents = ReadStringFromFile(deps_file)
      parse_results = _ParseRevisionsFromDEPSFileManually(deps_file_contents)
      results = {}
      for depot_name, depot_revision in parse_results.iteritems():
        depot_revision = depot_revision.strip('@')
        logging.warn(depot_name, depot_revision)
        for cur_name, cur_data in bisect_utils.DEPOT_DEPS_NAME.iteritems():
          if cur_data.get('deps_var') == depot_name:
            src_name = cur_name
            results[src_name] = depot_revision
            break
      return results

  def _Get3rdPartyRevisions(self, depot):
    """Parses the DEPS file to determine WebKit/v8/etc... versions.

    Args:
      depot: A depot name. Should be in the DEPOT_NAMES list.

    Returns:
      A dict in the format {depot: revision} if successful, otherwise None.
    """
    cwd = os.getcwd()
    self.depot_registry.ChangeToDepotDir(depot)

    results = {}

    if depot == 'chromium' or depot == 'android-chrome':
      results = self._ParseRevisionsFromDEPSFile(depot)
      os.chdir(cwd)

    if depot == 'v8':
      # We can't try to map the trunk revision to bleeding edge yet, because
      # we don't know which direction to try to search in. Have to wait until
      # the bisect has narrowed the results down to 2 v8 rolls.
      results['v8_bleeding_edge'] = None

    return results

  def BackupOrRestoreOutputDirectory(self, restore=False, build_type='Release'):
    """Backs up or restores build output directory based on restore argument.

    Args:
      restore: Indicates whether to restore or backup. Default is False(Backup)
      build_type: Target build type ('Release', 'Debug', 'Release_x64' etc.)

    Returns:
      Path to backup or restored location as string. otherwise None if it fails.
    """
    build_dir = os.path.abspath(
        builder.GetBuildOutputDirectory(self.opts, self.src_cwd))
    source_dir = os.path.join(build_dir, build_type)
    destination_dir = os.path.join(build_dir, '%s.bak' % build_type)
    if restore:
      source_dir, destination_dir = destination_dir, source_dir
    if os.path.exists(source_dir):
      RemoveDirectoryTree(destination_dir)
      shutil.move(source_dir, destination_dir)
      return destination_dir
    return None

  def _DownloadAndUnzipBuild(self, revision, depot, build_type='Release',
                             create_patch=False):
    """Downloads the build archive for the given revision.

    Args:
      revision: The git revision to download.
      depot: The name of a dependency repository. Should be in DEPOT_NAMES.
      build_type: Target build type, e.g. Release', 'Debug', 'Release_x64' etc.
      create_patch: Create a patch with any locally modified files.

    Returns:
      True if download succeeds, otherwise False.
    """
    patch = None
    patch_sha = None
    if depot not in ('chromium', 'android-chrome'):
      # Create a DEPS patch with new revision for dependency repository.
      self._CreateDEPSPatch(depot, revision)
      create_patch = True

    if create_patch:
      revision, patch = self._CreatePatch(revision)

    if patch:
      # Get the SHA of the DEPS changes patch.
      patch_sha = GetSHA1HexDigest(patch)

      # Update the DEPS changes patch with a patch to create a new file named
      # 'DEPS.sha' and add patch_sha evaluated above to it.
      patch = '%s\n%s' % (patch, DEPS_SHA_PATCH % {'deps_sha': patch_sha})

    build_dir = builder.GetBuildOutputDirectory(self.opts, self.src_cwd)
    downloaded_file = self._WaitForBuildDownload(
        revision, build_dir, deps_patch=patch, deps_patch_sha=patch_sha)
    if not downloaded_file:
      return False
    return self._UnzipAndMoveBuildProducts(downloaded_file, build_dir,
                                           build_type=build_type)

  def _WaitForBuildDownload(self, revision, build_dir, deps_patch=None,
                            deps_patch_sha=None):
    """Tries to download a zip archive for a build.

    This involves seeing whether the archive is already available, and if not,
    then requesting a build and waiting before downloading.

    Args:
      revision: A git commit hash.
      build_dir: The directory to download the build into.
      deps_patch: A patch which changes a dependency repository revision in
          the DEPS, if applicable.
      deps_patch_sha: The SHA1 hex digest of the above patch.

    Returns:
      File path of the downloaded file if successful, otherwise None.
    """
    bucket_name, remote_path = fetch_build.GetBucketAndRemotePath(
        revision, builder_type=self.opts.builder_type,
        target_arch=self.opts.target_arch,
        target_platform=self.opts.target_platform,
        deps_patch_sha=deps_patch_sha,
        extra_src=self.opts.extra_src)
    output_dir = os.path.abspath(build_dir)
    fetch_build_func = lambda: fetch_build.FetchFromCloudStorage(
        bucket_name, remote_path, output_dir)

    is_available = fetch_build.BuildIsAvailable(bucket_name, remote_path)
    if is_available:
      return fetch_build_func()

    # When build archive doesn't exist, make a request and wait.
    return self._RequestBuildAndWait(
        revision, fetch_build_func, deps_patch=deps_patch)

  def _RequestBuildAndWait(self, git_revision, fetch_build_func,
                           deps_patch=None):
    """Triggers a try job for a build job.

    This function prepares and starts a try job for a builder, and waits for
    the archive to be produced and archived. Once the build is ready it is
    downloaded.

    For performance tests, builders on the tryserver.chromium.perf are used.

    TODO(qyearsley): Make this function take "builder_type" as a parameter
    and make requests to different bot names based on that parameter.

    Args:
      git_revision: A git commit hash.
      fetch_build_func: Function to check and download build from cloud storage.
      deps_patch: DEPS patch string, used when bisecting dependency repos.

    Returns:
      Downloaded archive file path when requested build exists and download is
      successful, otherwise None.
    """
    if not fetch_build_func:
      return None

    # Create a unique ID for each build request posted to try server builders.
    # This ID is added to "Reason" property of the build.
    build_request_id = GetSHA1HexDigest(
        '%s-%s-%s' % (git_revision, deps_patch, time.time()))

    # Revert any changes to DEPS file.
    bisect_utils.CheckRunGit(['reset', '--hard', 'HEAD'], cwd=self.src_cwd)

    builder_name, build_timeout = fetch_build.GetBuilderNameAndBuildTime(
        builder_type=self.opts.builder_type,
        target_arch=self.opts.target_arch,
        target_platform=self.opts.target_platform,
        extra_src=self.opts.extra_src)

    try:
      _StartBuilderTryJob(self.opts.builder_type, git_revision, builder_name,
                          job_name=build_request_id, patch=deps_patch)
    except RunGitError as e:
      logging.warn('Failed to post builder try job for revision: [%s].\n'
                   'Error: %s', git_revision, e)
      return None

    # Get the buildbot master URL to monitor build status.
    buildbot_server_url = fetch_build.GetBuildBotUrl(
        builder_type=self.opts.builder_type,
        target_arch=self.opts.target_arch,
        target_platform=self.opts.target_platform,
        extra_src=self.opts.extra_src)

    archive_filename, error_msg = _WaitUntilBuildIsReady(
        fetch_build_func, builder_name, build_request_id, build_timeout,
        buildbot_server_url)
    if not archive_filename:
      logging.warn('%s [revision: %s]', error_msg, git_revision)
    return archive_filename

  def _UnzipAndMoveBuildProducts(self, downloaded_file, build_dir,
                                 build_type='Release'):
    """Unzips the build archive and moves it to the build output directory.

    The build output directory is wherever the binaries are expected to
    be in order to start Chrome and run tests.

    TODO: Simplify and clarify this method if possible.

    Args:
      downloaded_file: File path of the downloaded zip file.
      build_dir: Directory where the the zip file was downloaded to.
      build_type: "Release" or "Debug".

    Returns:
      True if successful, False otherwise.
    """
    abs_build_dir = os.path.abspath(build_dir)
    output_dir = os.path.join(abs_build_dir, self.GetZipFileBuildDirName())
    logging.info('EXPERIMENTAL RUN, _UnzipAndMoveBuildProducts locals %s',
                 str(locals()))

    try:
      RemoveDirectoryTree(output_dir)
      self.BackupOrRestoreOutputDirectory(restore=False)
      # Build output directory based on target(e.g. out/Release, out/Debug).
      target_build_output_dir = os.path.join(abs_build_dir, build_type)

      logging.info('Extracting "%s" to "%s"', downloaded_file, abs_build_dir)
      fetch_build.Unzip(downloaded_file, abs_build_dir)

      if not os.path.exists(output_dir):
        # Due to recipe changes, the builds extract folder contains
        # out/Release instead of full-build-<platform>/Release.
        if os.path.exists(os.path.join(abs_build_dir, 'out', build_type)):
          output_dir = os.path.join(abs_build_dir, 'out', build_type)
        else:
          raise IOError('Missing extracted folder %s ' % output_dir)

      logging.info('Moving build from %s to %s',
                   output_dir, target_build_output_dir)
      shutil.move(output_dir, target_build_output_dir)
      return True
    except Exception as e:
      logging.info('Something went wrong while extracting archive file: %s', e)
      self.BackupOrRestoreOutputDirectory(restore=True)
      # Cleanup any leftovers from unzipping.
      if os.path.exists(output_dir):
        RemoveDirectoryTree(output_dir)
    finally:
      # Delete downloaded archive
      if os.path.exists(downloaded_file):
        os.remove(downloaded_file)
    return False

  @staticmethod
  def GetZipFileBuildDirName():
    """Gets the base file name of the zip file.

    After extracting the zip file, this is the name of the directory where
    the build files are expected to be. Possibly.

    TODO: Make sure that this returns the actual directory name where the
    Release or Debug directory is inside of the zip files. This probably
    depends on the builder recipe, and may depend on whether the builder is
    a perf builder or full builder.

    Returns:
      The name of the directory inside a build archive which is expected to
      contain a Release or Debug directory.
    """
    if bisect_utils.IsWindowsHost():
      return 'full-build-win32'
    if bisect_utils.IsLinuxHost():
      return 'full-build-linux'
    if bisect_utils.IsMacHost():
      return 'full-build-mac'
    raise NotImplementedError('Unknown platform "%s".' % sys.platform)

  def IsDownloadable(self, depot):
    """Checks if build can be downloaded based on target platform and depot."""
    if (self.opts.target_platform in ['chromium', 'android', 'android-chrome']
        and self.opts.builder_type):
      # In case of android-chrome platform, download archives only for
      # android-chrome depot; for other depots such as chromium, v8, skia
      # etc., build the binary locally.
      if self.opts.target_platform == 'android-chrome':
        return depot == 'android-chrome'
      else:
        return (depot == 'chromium' or
                'chromium' in bisect_utils.DEPOT_DEPS_NAME[depot]['from'] or
                'v8' in bisect_utils.DEPOT_DEPS_NAME[depot]['from'])
    return False

  def UpdateDepsContents(self, deps_contents, depot, git_revision, deps_key):
    """Returns modified version of DEPS file contents.

    Args:
      deps_contents: DEPS file content.
      depot: Current depot being bisected.
      git_revision: A git hash to be updated in DEPS.
      deps_key: Key in vars section of DEPS file to be searched.

    Returns:
      Updated DEPS content as string if deps key is found, otherwise None.
    """
    # Check whether the depot and revision pattern in DEPS file vars
    # e.g. for webkit the format is "webkit_revision": "12345".
    deps_revision = re.compile(r'(?<="%s": ")([0-9]+)(?=")' % deps_key,
                               re.MULTILINE)
    new_data = None
    if re.search(deps_revision, deps_contents):
      commit_position = source_control.GetCommitPosition(
          git_revision, self.depot_registry.GetDepotDir(depot))
      if not commit_position:
        logging.warn('Could not determine commit position for %s', git_revision)
        return None
      # Update the revision information for the given depot
      new_data = re.sub(deps_revision, str(commit_position), deps_contents)
    else:
      # Check whether the depot and revision pattern in DEPS file vars
      # e.g. for webkit the format is "webkit_revision": "559a6d4ab7a84c539..".
      deps_revision = re.compile(
          r'(?<=["\']%s["\']: ["\'])([a-fA-F0-9]{40})(?=["\'])' % deps_key,
          re.MULTILINE)
      if re.search(deps_revision, deps_contents):
        new_data = re.sub(deps_revision, git_revision, deps_contents)
    if new_data:
      # For v8_bleeding_edge revisions change V8 branch in order
      # to fetch bleeding edge revision.
      if depot == 'v8_bleeding_edge':
        new_data = _UpdateV8Branch(new_data)
        if not new_data:
          return None
    return new_data

  def UpdateDeps(self, revision, depot, deps_file):
    """Updates DEPS file with new revision of dependency repository.

    This method search DEPS for a particular pattern in which depot revision
    is specified (e.g "webkit_revision": "123456"). If a match is found then
    it resolves the given git hash to SVN revision and replace it in DEPS file.

    Args:
      revision: A git hash revision of the dependency repository.
      depot: Current depot being bisected.
      deps_file: Path to DEPS file.

    Returns:
      True if DEPS file is modified successfully, otherwise False.
    """
    if not os.path.exists(deps_file):
      return False

    deps_var = bisect_utils.DEPOT_DEPS_NAME[depot]['deps_var']
    # Don't update DEPS file if deps_var is not set in DEPOT_DEPS_NAME.
    if not deps_var:
      logging.warn('DEPS update not supported for Depot: %s', depot)
      return False

    # Hack for Angle repository. In the DEPS file, "vars" dictionary variable
    # contains "angle_revision" key that holds git hash instead of SVN revision.
    # And sometime "angle_revision" key is not specified in "vars" variable.
    # In such cases check, "deps" dictionary variable that matches
    # angle.git@[a-fA-F0-9]{40}$ and replace git hash.
    if depot == 'angle':
      return _UpdateDEPSForAngle(revision, depot, deps_file)

    try:
      deps_contents = ReadStringFromFile(deps_file)
      updated_deps_content = self.UpdateDepsContents(
          deps_contents, depot, revision, deps_var)
      # Write changes to DEPS file
      if updated_deps_content:
        WriteStringToFile(updated_deps_content, deps_file)
        return True
    except IOError, e:
      logging.warn('Something went wrong while updating DEPS file. [%s]', e)
    return False

  def _CreateDEPSPatch(self, depot, revision):
    """Checks out the DEPS file at the specified revision and modifies it.

    Args:
      depot: Current depot being bisected.
      revision: A git hash revision of the dependency repository.
    """
    deps_file_path = os.path.join(self.src_cwd, bisect_utils.FILE_DEPS)
    if not os.path.exists(deps_file_path):
      raise RuntimeError('DEPS file does not exists.[%s]' % deps_file_path)
    # Get current chromium revision (git hash).
    cmd = ['rev-parse', 'HEAD']
    chromium_sha = bisect_utils.CheckRunGit(cmd).strip()
    if not chromium_sha:
      raise RuntimeError('Failed to determine Chromium revision for %s' %
                         revision)
    if ('chromium' in bisect_utils.DEPOT_DEPS_NAME[depot]['from'] or
        'v8' in bisect_utils.DEPOT_DEPS_NAME[depot]['from']):
      # Checkout DEPS file for the current chromium revision.
      if not source_control.CheckoutFileAtRevision(
          bisect_utils.FILE_DEPS, chromium_sha, cwd=self.src_cwd):
        raise RuntimeError(
            'DEPS checkout Failed for chromium revision : [%s]' % chromium_sha)

      if not self.UpdateDeps(revision, depot, deps_file_path):
        raise RuntimeError(
            'Failed to update DEPS file for chromium: [%s]' % chromium_sha)

  def _CreatePatch(self, revision):
    """Creates a patch from currently modified files.

    Args:
      depot: Current depot being bisected.
      revision: A git hash revision of the dependency repository.

    Returns:
      A tuple with git hash of chromium revision and DEPS patch text.
    """
    # Get current chromium revision (git hash).
    chromium_sha = bisect_utils.CheckRunGit(['rev-parse', 'HEAD']).strip()
    if not chromium_sha:
      raise RuntimeError('Failed to determine Chromium revision for %s' %
                         revision)
    # Checkout DEPS file for the current chromium revision.
    diff_command = [
        'diff',
        '--src-prefix=',
        '--dst-prefix=',
        '--no-ext-diff',
        'HEAD',
    ]
    diff_text = bisect_utils.CheckRunGit(diff_command)
    return (chromium_sha, ChangeBackslashToSlashInPatch(diff_text))

  def ObtainBuild(
      self, depot, revision=None, create_patch=False):
    """Obtains a build by either downloading or building directly.

    Args:
      depot: Dependency repository name.
      revision: A git commit hash. If None is given, the currently checked-out
          revision is built.
      create_patch: Create a patch with any locally modified files.

    Returns:
      True for success.
    """
    if self.opts.debug_ignore_build:
      return True

    build_success = False
    cwd = os.getcwd()
    os.chdir(self.src_cwd)
    # Fetch build archive for the given revision from the cloud storage when
    # the storage bucket is passed.
    if self.IsDownloadable(depot) and revision:
      build_success = self._DownloadAndUnzipBuild(
          revision, depot, build_type='Release', create_patch=create_patch)
    else:
      # Print the current environment set on the machine.
      print 'Full Environment:'
      for key, value in sorted(os.environ.items()):
        print '%s: %s' % (key, value)
      # Print the environment before proceeding with compile.
      sys.stdout.flush()
      build_success = self.builder.Build(depot, self.opts)
    os.chdir(cwd)
    return build_success

  def RunGClientHooks(self):
    """Runs gclient with runhooks command.

    Returns:
      True if gclient reports no errors.
    """
    if self.opts.debug_ignore_build:
      return True
    # Some "runhooks" calls create symlinks that other (older?) versions
    # do not handle correctly causing the build to fail.  We want to avoid
    # clearing the entire out/ directory so that changes close together will
    # build faster so we just clear out all symlinks on the expectation that
    # the next "runhooks" call will recreate everything properly.  Ignore
    # failures (like Windows that doesn't have "find").
    try:
      bisect_utils.RunProcess(
          ['find', 'out/', '-type', 'l', '-exec', 'rm', '-f', '{}', ';'],
          cwd=self.src_cwd, shell=False)
    except OSError:
      pass
    return not bisect_utils.RunGClient(['runhooks'], cwd=self.src_cwd)

  def _IsBisectModeUsingMetric(self):
    return self.opts.bisect_mode in [bisect_utils.BISECT_MODE_MEAN,
                                     bisect_utils.BISECT_MODE_STD_DEV]

  def _IsBisectModeReturnCode(self):
    return self.opts.bisect_mode in [bisect_utils.BISECT_MODE_RETURN_CODE]

  def _IsBisectModeStandardDeviation(self):
    return self.opts.bisect_mode in [bisect_utils.BISECT_MODE_STD_DEV]

  def RunPerformanceTestAndParseResults(
      self, command_to_run, metric, reset_on_first_run=False,
      upload_on_last_run=False, results_label=None, test_run_multiplier=1,
      allow_flakes=True):
    """Runs a performance test on the current revision and parses the results.

    Args:
      command_to_run: The command to be run to execute the performance test.
      metric: The metric to parse out from the results of the performance test.
          This is the result chart name and trace name, separated by slash.
          May be None for perf try jobs.
      reset_on_first_run: If True, pass the flag --reset-results on first run.
      upload_on_last_run: If True, pass the flag --upload-results on last run.
      results_label: A value for the option flag --results-label.
          The arguments reset_on_first_run, upload_on_last_run and results_label
          are all ignored if the test is not a Telemetry test.
      test_run_multiplier: Factor by which to multiply the number of test runs
          and the timeout period specified in self.opts.
      allow_flakes: Report success even if some tests fail to run.

    Returns:
      (values dict, 0) if --debug_ignore_perf_test was passed.
      (values dict, 0, test output) if the test was run successfully.
      (error message, -1) if the test couldn't be run.
      (error message, -1, test output) if the test ran but there was an error.
    """
    success_code, failure_code = 0, -1

    if self.opts.debug_ignore_perf_test:
      fake_results = {
          'mean': 0.0,
          'std_err': 0.0,
          'std_dev': 0.0,
          'values': [0.0]
      }

      # When debug_fake_test_mean is set, its value is returned as the mean
      # and the flag is cleared so that further calls behave as if it wasn't
      # set (returning the fake_results dict as defined above).
      if self.opts.debug_fake_first_test_mean:
        fake_results['mean'] = float(self.opts.debug_fake_first_test_mean)
        self.opts.debug_fake_first_test_mean = 0

      return (fake_results, success_code)

    # For Windows platform set posix=False, to parse windows paths correctly.
    # On Windows, path separators '\' or '\\' are replace by '' when posix=True,
    # refer to http://bugs.python.org/issue1724822. By default posix=True.
    args = shlex.split(command_to_run, posix=not bisect_utils.IsWindowsHost())

    if not _GenerateProfileIfNecessary(args):
      err_text = 'Failed to generate profile for performance test.'
      return (err_text, failure_code)

    is_telemetry = bisect_utils.IsTelemetryCommand(command_to_run)

    start_time = time.time()

    metric_values = []
    output_of_all_runs = ''
    repeat_count = self.opts.repeat_test_count * test_run_multiplier
    return_codes = []
    for i in xrange(repeat_count):
      # Can ignore the return code since if the tests fail, it won't return 0.
      current_args = copy.copy(args)
      if is_telemetry:
        if i == 0 and reset_on_first_run:
          current_args.append('--reset-results')
        if i == self.opts.repeat_test_count - 1 and upload_on_last_run:
          current_args.append('--upload-results')
        if results_label:
          current_args.append('--results-label=%s' % results_label)
      try:
        output, return_code = bisect_utils.RunProcessAndRetrieveOutput(
            current_args, cwd=self.src_cwd)
        return_codes.append(return_code)
      except OSError, e:
        if e.errno == errno.ENOENT:
          err_text = ('Something went wrong running the performance test. '
                      'Please review the command line:\n\n')
          if 'src/' in ' '.join(args):
            err_text += ('Check that you haven\'t accidentally specified a '
                         'path with src/ in the command.\n\n')
          err_text += ' '.join(args)
          err_text += '\n'

          return (err_text, failure_code)
        raise

      output_of_all_runs += output
      if self.opts.output_buildbot_annotations:
        print output

      if metric and self._IsBisectModeUsingMetric():
        parsed_metric = _ParseMetricValuesFromOutput(metric, output)
        if parsed_metric:
          metric_values += parsed_metric
        # If we're bisecting on a metric (ie, changes in the mean or
        # standard deviation) and no metric values are produced, bail out.
        if not metric_values:
          break
      elif self._IsBisectModeReturnCode():
        metric_values.append(return_code)
        # If there's a failed test, we can bail out early.
        if return_code:
          break

      elapsed_minutes = (time.time() - start_time) / 60.0
      time_limit = self.opts.max_time_minutes * test_run_multiplier
      if elapsed_minutes >= time_limit:
        break

    if metric and len(metric_values) == 0:
      err_text = 'Metric %s was not found in the test output.' % metric
      # TODO(qyearsley): Consider also getting and displaying a list of metrics
      # that were found in the output here.
      return (err_text, failure_code, output_of_all_runs)

    # If we're bisecting on return codes, we're really just looking for zero vs
    # non-zero.
    values = {}
    if self._IsBisectModeReturnCode():
      # If any of the return codes is non-zero, output 1.
      overall_return_code = 0 if (
          all(current_value == 0 for current_value in metric_values)) else 1

      values = {
          'mean': overall_return_code,
          'std_err': 0.0,
          'std_dev': 0.0,
          'values': metric_values,
      }

      print 'Results of performance test: Command returned with %d' % (
          overall_return_code)
      print
    elif metric:
      # Need to get the average value if there were multiple values.
      truncated_mean = math_utils.TruncatedMean(
          metric_values, self.opts.truncate_percent)
      standard_err = math_utils.StandardError(metric_values)
      standard_dev = math_utils.StandardDeviation(metric_values)

      if self._IsBisectModeStandardDeviation():
        metric_values = [standard_dev]

      values = {
          'mean': truncated_mean,
          'std_err': standard_err,
          'std_dev': standard_dev,
          'values': metric_values,
      }

      print 'Results of performance test: %12f %12f' % (
          truncated_mean, standard_err)
      print

    overall_success = success_code
    if not allow_flakes and not self._IsBisectModeReturnCode():
      overall_success = (
          success_code
          if (all(current_value == 0 for current_value in return_codes))
              else failure_code)

    return (values, overall_success, output_of_all_runs)

  def PerformPreBuildCleanup(self):
    """Performs cleanup between runs."""
    print 'Cleaning up between runs.'
    print

    # Leaving these .pyc files around between runs may disrupt some perf tests.
    for (path, _, files) in os.walk(self.src_cwd):
      for cur_file in files:
        if cur_file.endswith('.pyc'):
          path_to_file = os.path.join(path, cur_file)
          os.remove(path_to_file)

  def _RunPostSync(self, _depot):
    """Performs any work after syncing.

    Args:
      depot: Depot name.

    Returns:
      True if successful.
    """
    if 'android' in self.opts.target_platform:
      if not builder.SetupAndroidBuildEnvironment(
          self.opts, path_to_src=self.src_cwd):
        return False

    return self.RunGClientHooks()

  @staticmethod
  def ShouldSkipRevision(depot, revision):
    """Checks whether a particular revision can be safely skipped.

    Some commits can be safely skipped (such as a DEPS roll for the repos
    still using .DEPS.git), since the tool is git based those changes
    would have no effect.

    Args:
      depot: The depot being bisected.
      revision: Current revision we're synced to.

    Returns:
      True if we should skip building/testing this revision.
    """
    # Skips revisions with DEPS on android-chrome.
    if depot == 'android-chrome':
      cmd = ['diff-tree', '--no-commit-id', '--name-only', '-r', revision]
      output = bisect_utils.CheckRunGit(cmd)

      files = output.splitlines()

      if len(files) == 1 and files[0] == 'DEPS':
        return True

    return False

  def RunTest(self, revision, depot, command, metric, skippable=False,
              skip_sync=False, create_patch=False, force_build=False,
              test_run_multiplier=1):
    """Performs a full sync/build/run of the specified revision.

    Args:
      revision: The revision to sync to.
      depot: The depot that's being used at the moment (src, webkit, etc.)
      command: The command to execute the performance test.
      metric: The performance metric being tested.
      skip_sync: Skip the sync step.
      create_patch: Create a patch with any locally modified files.
      force_build: Force a local build.
      test_run_multiplier: Factor by which to multiply the given number of runs
          and the set timeout period.

    Returns:
      On success, a tuple containing the results of the performance test.
      Otherwise, a tuple with the error message.
    """
    logging.info('Running RunTest with rev "%s", command "%s"',
                 revision, command)
    # Decide which sync program to use.
    sync_client = None
    if depot == 'chromium' or depot == 'android-chrome':
      sync_client = 'gclient'

    # Do the syncing for all depots.
    if not (self.opts.debug_ignore_sync or skip_sync):
      if not self._SyncRevision(depot, revision, sync_client):
        return ('Failed to sync: [%s]' % str(revision), BUILD_RESULT_FAIL)

    # Try to do any post-sync steps. This may include "gclient runhooks".
    if not self._RunPostSync(depot):
      return ('Failed to run [gclient runhooks].', BUILD_RESULT_FAIL)

    # Skip this revision if it can be skipped.
    if skippable and self.ShouldSkipRevision(depot, revision):
      return ('Skipped revision: [%s]' % str(revision),
              BUILD_RESULT_SKIPPED)

    # Obtain a build for this revision. This may be done by requesting a build
    # from another builder, waiting for it and downloading it.
    start_build_time = time.time()
    revision_to_build = revision if not force_build else None
    build_success = self.ObtainBuild(
        depot, revision=revision_to_build, create_patch=create_patch)
    if not build_success:
      return ('Failed to build revision: [%s]' % str(revision),
              BUILD_RESULT_FAIL)
    after_build_time = time.time()

    # Run the command and get the results.
    results = self.RunPerformanceTestAndParseResults(
        command, metric, test_run_multiplier=test_run_multiplier)

    # Restore build output directory once the tests are done, to avoid
    # any discrepancies.
    if self.IsDownloadable(depot) and revision:
      self.BackupOrRestoreOutputDirectory(restore=True)

    # A value other than 0 indicates that the test couldn't be run, and results
    # should also include an error message.
    if results[1] != 0:
      return results

    external_revisions = self._Get3rdPartyRevisions(depot)

    if not external_revisions is None:
      return (results[0], results[1], external_revisions,
              time.time() - after_build_time, after_build_time -
              start_build_time)
    else:
      return ('Failed to parse DEPS file for external revisions.',
              BUILD_RESULT_FAIL)

  def _SyncRevision(self, depot, revision, sync_client):
    """Syncs depot to particular revision.

    Args:
      depot: The depot that's being used at the moment (src, webkit, etc.)
      revision: The revision to sync to.
      sync_client: Program used to sync, e.g. "gclient". Can be None.

    Returns:
      True if successful, False otherwise.
    """
    self.depot_registry.ChangeToDepotDir(depot)

    if sync_client:
      self.PerformPreBuildCleanup()

    # When using gclient to sync, you need to specify the depot you
    # want so that all the dependencies sync properly as well.
    # i.e. gclient sync src@<SHA1>
    if sync_client == 'gclient' and revision:
      revision = '%s@%s' % (bisect_utils.DEPOT_DEPS_NAME[depot]['src'],
                            revision)
      if depot == 'chromium' and self.opts.target_platform == 'android-chrome':
        return self._SyncRevisionsForAndroidChrome(revision)

    return source_control.SyncToRevision(revision, sync_client)

  def _SyncRevisionsForAndroidChrome(self, revision):
    """Syncs android-chrome and chromium repos to particular revision.

    This is a special case for android-chrome as the gclient sync for chromium
    overwrites the android-chrome revision to TOT. Therefore both the repos
    are synced to known revisions.

    Args:
      revision: Git hash of the Chromium to sync.

    Returns:
      True if successful, False otherwise.
    """
    revisions_list = [revision]
    current_android_rev = source_control.GetCurrentRevision(
        self.depot_registry.GetDepotDir('android-chrome'))
    revisions_list.append(
        '%s@%s' % (bisect_utils.DEPOT_DEPS_NAME['android-chrome']['src'],
                   current_android_rev))
    return not bisect_utils.RunGClientAndSync(revisions_list)

  def _CheckIfRunPassed(self, current_value, known_good_value, known_bad_value):
    """Given known good and bad values, decide if the current_value passed
    or failed.

    Args:
      current_value: The value of the metric being checked.
      known_bad_value: The reference value for a "failed" run.
      known_good_value: The reference value for a "passed" run.

    Returns:
      True if the current_value is closer to the known_good_value than the
      known_bad_value.
    """
    if self.opts.bisect_mode == bisect_utils.BISECT_MODE_STD_DEV:
      dist_to_good_value = abs(current_value['std_dev'] -
                               known_good_value['std_dev'])
      dist_to_bad_value = abs(current_value['std_dev'] -
                              known_bad_value['std_dev'])
    else:
      dist_to_good_value = abs(current_value['mean'] - known_good_value['mean'])
      dist_to_bad_value = abs(current_value['mean'] - known_bad_value['mean'])

    return dist_to_good_value < dist_to_bad_value

  def _GetV8BleedingEdgeFromV8TrunkIfMappable(
      self, revision, bleeding_edge_branch):
    """Gets v8 bleeding edge revision mapped to v8 revision in trunk.

    Args:
      revision: A trunk V8 revision mapped to bleeding edge revision.
      bleeding_edge_branch: Branch used to perform lookup of bleeding edge
                            revision.
    Return:
      A mapped bleeding edge revision if found, otherwise None.
    """
    commit_position = source_control.GetCommitPosition(revision)

    if bisect_utils.IsStringInt(commit_position):
      # V8 is tricky to bisect, in that there are only a few instances when
      # we can dive into bleeding_edge and get back a meaningful result.
      # Try to detect a V8 "business as usual" case, which is when:
      #  1. trunk revision N has description "Version X.Y.Z"
      #  2. bleeding_edge revision (N-1) has description "Prepare push to
      #     trunk. Now working on X.Y.(Z+1)."
      #
      # As of 01/24/2014, V8 trunk descriptions are formatted:
      # "Version 3.X.Y (based on bleeding_edge revision rZ)"
      # So we can just try parsing that out first and fall back to the old way.
      v8_dir = self.depot_registry.GetDepotDir('v8')
      v8_bleeding_edge_dir = self.depot_registry.GetDepotDir('v8_bleeding_edge')

      revision_info = source_control.QueryRevisionInfo(revision, cwd=v8_dir)
      version_re = re.compile("Version (?P<values>[0-9,.]+)")
      regex_results = version_re.search(revision_info['subject'])
      if regex_results:
        git_revision = None
        if 'based on bleeding_edge' in revision_info['subject']:
          try:
            bleeding_edge_revision = revision_info['subject'].split(
                'bleeding_edge revision r')[1]
            bleeding_edge_revision = int(bleeding_edge_revision.split(')')[0])
            bleeding_edge_url = ('https://v8.googlecode.com/svn/branches/'
                                 'bleeding_edge@%s' % bleeding_edge_revision)
            cmd = ['log',
                   '--format=%H',
                   '--grep',
                   bleeding_edge_url,
                   '-1',
                   bleeding_edge_branch]
            output = bisect_utils.CheckRunGit(cmd, cwd=v8_dir)
            if output:
              git_revision = output.strip()
            return git_revision
          except (IndexError, ValueError):
            pass
        else:
          # V8 rolls description changed after V8 git migration, new description
          # includes "Version 3.X.Y (based on <git hash>)"
          try:
            rxp = re.compile('based on (?P<git_revision>[a-fA-F0-9]+)')
            re_results = rxp.search(revision_info['subject'])
            if re_results:
              return re_results.group('git_revision')
          except (IndexError, ValueError):
            pass
        if not git_revision:
          # Wasn't successful, try the old way of looking for "Prepare push to"
          git_revision = source_control.ResolveToRevision(
              int(commit_position) - 1, 'v8_bleeding_edge',
              bisect_utils.DEPOT_DEPS_NAME, -1, cwd=v8_bleeding_edge_dir)

          if git_revision:
            revision_info = source_control.QueryRevisionInfo(
                git_revision, cwd=v8_bleeding_edge_dir)

            if 'Prepare push to trunk' in revision_info['subject']:
              return git_revision
    return None

  def _GetNearestV8BleedingEdgeFromTrunk(
      self, revision, v8_branch, bleeding_edge_branch, search_forward=True):
    """Gets the nearest V8 roll and maps to bleeding edge revision.

    V8 is a bit tricky to bisect since it isn't just rolled out like blink.
    Each revision on trunk might just be whatever was in bleeding edge, rolled
    directly out. Or it could be some mixture of previous v8 trunk versions,
    with bits and pieces cherry picked out from bleeding edge. In order to
    bisect, we need both the before/after versions on trunk v8 to be just pushes
    from bleeding edge. With the V8 git migration, the branches got switched.
    a) master (external/v8) == candidates (v8/v8)
    b) bleeding_edge (external/v8) == master (v8/v8)

    Args:
      revision: A V8 revision to get its nearest bleeding edge revision
      search_forward: Searches forward if True, otherwise search backward.

    Return:
      A mapped bleeding edge revision if found, otherwise None.
    """
    cwd = self.depot_registry.GetDepotDir('v8')
    cmd = ['log', '--format=%ct', '-1', revision]
    output = bisect_utils.CheckRunGit(cmd, cwd=cwd)
    commit_time = int(output)
    commits = []
    if search_forward:
      cmd = ['log',
             '--format=%H',
             '--after=%d' % commit_time,
             v8_branch,
             '--reverse']
      output = bisect_utils.CheckRunGit(cmd, cwd=cwd)
      output = output.split()
      commits = output
      #Get 10 git hashes immediately after the given commit.
      commits = commits[:10]
    else:
      cmd = ['log',
             '--format=%H',
             '-10',
             '--before=%d' % commit_time,
             v8_branch]
      output = bisect_utils.CheckRunGit(cmd, cwd=cwd)
      output = output.split()
      commits = output

    bleeding_edge_revision = None

    for c in commits:
      bleeding_edge_revision = self._GetV8BleedingEdgeFromV8TrunkIfMappable(
          c, bleeding_edge_branch)
      if bleeding_edge_revision:
        break

    return bleeding_edge_revision

  def _FillInV8BleedingEdgeInfo(self, min_revision_state, max_revision_state):
    cwd = self.depot_registry.GetDepotDir('v8')
    # when "remote.origin.url" is https://chromium.googlesource.com/v8/v8.git
    v8_branch = 'origin/candidates'
    bleeding_edge_branch = 'origin/master'

    # Support for the chromium revisions with external V8 repo.
    # ie https://chromium.googlesource.com/external/v8.git
    cmd = ['config', '--get', 'remote.origin.url']
    v8_repo_url = bisect_utils.CheckRunGit(cmd, cwd=cwd)

    if 'external/v8.git' in v8_repo_url:
      v8_branch = 'origin/master'
      bleeding_edge_branch = 'origin/bleeding_edge'

    r1 = self._GetNearestV8BleedingEdgeFromTrunk(
        min_revision_state.revision,
        v8_branch,
        bleeding_edge_branch,
        search_forward=True)
    r2 = self._GetNearestV8BleedingEdgeFromTrunk(
        max_revision_state.revision,
        v8_branch,
        bleeding_edge_branch,
        search_forward=False)
    min_revision_state.external['v8_bleeding_edge'] = r1
    max_revision_state.external['v8_bleeding_edge'] = r2

    if (not self._GetV8BleedingEdgeFromV8TrunkIfMappable(
            min_revision_state.revision, bleeding_edge_branch)
        or not self._GetV8BleedingEdgeFromV8TrunkIfMappable(
            max_revision_state.revision, bleeding_edge_branch)):
      self.warnings.append(
          'Trunk revisions in V8 did not map directly to bleeding_edge. '
          'Attempted to expand the range to find V8 rolls which did map '
          'directly to bleeding_edge revisions, but results might not be '
          'valid.')

  def _FindNextDepotToBisect(
      self, current_depot, min_revision_state, max_revision_state):
    """Decides which depot the script should dive into next (if any).

    Args:
      current_depot: Current depot being bisected.
      min_revision_state: State of the earliest revision in the bisect range.
      max_revision_state: State of the latest revision in the bisect range.

    Returns:
      Name of the depot to bisect next, or None.
    """
    external_depot = None
    for next_depot in bisect_utils.DEPOT_NAMES:
      if ('platform' in bisect_utils.DEPOT_DEPS_NAME[next_depot] and
          bisect_utils.DEPOT_DEPS_NAME[next_depot]['platform'] != os.name):
        continue

      if not (bisect_utils.DEPOT_DEPS_NAME[next_depot]['recurse']
              and min_revision_state.depot
              in bisect_utils.DEPOT_DEPS_NAME[next_depot]['from']):
        continue

      if current_depot == 'v8':
        # We grab the bleeding_edge info here rather than earlier because we
        # finally have the revision range. From that we can search forwards and
        # backwards to try to match trunk revisions to bleeding_edge.
        self._FillInV8BleedingEdgeInfo(min_revision_state, max_revision_state)

      if (min_revision_state.external.get(next_depot) ==
          max_revision_state.external.get(next_depot)):
        continue

      if (min_revision_state.external.get(next_depot) and
          max_revision_state.external.get(next_depot)):
        external_depot = next_depot
        break

    return external_depot

  def PrepareToBisectOnDepot(
      self, current_depot, start_revision, end_revision, previous_revision):
    """Changes to the appropriate directory and gathers a list of revisions
    to bisect between |start_revision| and |end_revision|.

    Args:
      current_depot: The depot we want to bisect.
      start_revision: Start of the revision range.
      end_revision: End of the revision range.
      previous_revision: The last revision we synced to on |previous_depot|.

    Returns:
      A list containing the revisions between |start_revision| and
      |end_revision| inclusive.
    """
    # Change into working directory of external library to run
    # subsequent commands.
    self.depot_registry.ChangeToDepotDir(current_depot)

    # V8 (and possibly others) is merged in periodically. Bisecting
    # this directory directly won't give much good info.
    if 'custom_deps' in bisect_utils.DEPOT_DEPS_NAME[current_depot]:
      config_path = os.path.join(self.src_cwd, '..')
      if bisect_utils.RunGClientAndCreateConfig(
          self.opts, bisect_utils.DEPOT_DEPS_NAME[current_depot]['custom_deps'],
          cwd=config_path):
        return []
      if bisect_utils.RunGClient(
          ['sync', '--revision', previous_revision], cwd=self.src_cwd):
        return []

    if current_depot == 'v8_bleeding_edge':
      self.depot_registry.ChangeToDepotDir('chromium')

      shutil.move('v8', 'v8.bak')
      shutil.move('v8_bleeding_edge', 'v8')

      self.cleanup_commands.append(['mv', 'v8', 'v8_bleeding_edge'])
      self.cleanup_commands.append(['mv', 'v8.bak', 'v8'])

      self.depot_registry.SetDepotDir(
          'v8_bleeding_edge', os.path.join(self.src_cwd, 'v8'))
      self.depot_registry.SetDepotDir(
          'v8', os.path.join(self.src_cwd, 'v8.bak'))

      self.depot_registry.ChangeToDepotDir(current_depot)

    depot_revision_list = self.GetRevisionList(current_depot,
                                               end_revision,
                                               start_revision)

    self.depot_registry.ChangeToDepotDir('chromium')

    return depot_revision_list

  def GatherReferenceValues(self, good_rev, bad_rev, cmd, metric, target_depot):
    """Gathers reference values by running the performance tests on the
    known good and bad revisions.

    Args:
      good_rev: The last known good revision where the performance regression
        has not occurred yet.
      bad_rev: A revision where the performance regression has already occurred.
      cmd: The command to execute the performance test.
      metric: The metric being tested for regression.

    Returns:
      A tuple with the results of building and running each revision.
    """
    bad_run_results = self.RunTest(bad_rev, target_depot, cmd, metric)

    good_run_results = None

    if not bad_run_results[1]:
      good_run_results = self.RunTest(good_rev, target_depot, cmd, metric)

    return (bad_run_results, good_run_results)

  def PrintRevisionsToBisectMessage(self, revision_list, depot):
    if self.opts.output_buildbot_annotations:
      step_name = 'Bisection Range: [%s:%s - %s]' % (depot, revision_list[-1],
                                                     revision_list[0])
      bisect_utils.OutputAnnotationStepStart(step_name)

    print
    print 'Revisions to bisect on [%s]:' % depot
    for revision_id in revision_list:
      print '  -> %s' % (revision_id, )
    print

    if self.opts.output_buildbot_annotations:
      bisect_utils.OutputAnnotationStepClosed()

  def NudgeRevisionsIfDEPSChange(self, bad_revision, good_revision,
                                 good_svn_revision=None):
    """Checks to see if changes to DEPS file occurred, and that the revision
    range also includes the change to .DEPS.git. If it doesn't, attempts to
    expand the revision range to include it.

    Args:
      bad_revision: First known bad git revision.
      good_revision: Last known good git revision.
      good_svn_revision: Last known good svn revision.

    Returns:
      A tuple with the new bad and good revisions.
    """
    # DONOT perform nudge because at revision 291563 .DEPS.git was removed
    # and source contain only DEPS file for dependency changes.
    if good_svn_revision >= 291563:
      return (bad_revision, good_revision)

    if self.opts.target_platform == 'chromium':
      changes_to_deps = source_control.QueryFileRevisionHistory(
          bisect_utils.FILE_DEPS, good_revision, bad_revision)

      if changes_to_deps:
        # DEPS file was changed, search from the oldest change to DEPS file to
        # bad_revision to see if there are matching .DEPS.git changes.
        oldest_deps_change = changes_to_deps[-1]
        changes_to_gitdeps = source_control.QueryFileRevisionHistory(
            bisect_utils.FILE_DEPS_GIT, oldest_deps_change, bad_revision)

        if len(changes_to_deps) != len(changes_to_gitdeps):
          # Grab the timestamp of the last DEPS change
          cmd = ['log', '--format=%ct', '-1', changes_to_deps[0]]
          output = bisect_utils.CheckRunGit(cmd)
          commit_time = int(output)

          # Try looking for a commit that touches the .DEPS.git file in the
          # next 15 minutes after the DEPS file change.
          cmd = [
              'log', '--format=%H', '-1',
              '--before=%d' % (commit_time + 900),
              '--after=%d' % commit_time,
              'origin/master', '--', bisect_utils.FILE_DEPS_GIT
          ]
          output = bisect_utils.CheckRunGit(cmd)
          output = output.strip()
          if output:
            self.warnings.append(
                'Detected change to DEPS and modified '
                'revision range to include change to .DEPS.git')
            return (output, good_revision)
          else:
            self.warnings.append(
                'Detected change to DEPS but couldn\'t find '
                'matching change to .DEPS.git')
    return (bad_revision, good_revision)

  def CheckIfRevisionsInProperOrder(
      self, target_depot, good_revision, bad_revision):
    """Checks that |good_revision| is an earlier revision than |bad_revision|.

    Args:
      good_revision: Number/tag of the known good revision.
      bad_revision: Number/tag of the known bad revision.

    Returns:
      True if the revisions are in the proper order (good earlier than bad).
    """
    cwd = self.depot_registry.GetDepotDir(target_depot)
    good_position = source_control.GetCommitPosition(good_revision, cwd)
    bad_position = source_control.GetCommitPosition(bad_revision, cwd)
    # Compare commit timestamp for repos that don't support commit position.
    if not (bad_position and good_position):
      logging.info('Could not get commit positions for revisions %s and %s in '
                   'depot %s', good_position, bad_position, target_depot)
      good_position = source_control.GetCommitTime(good_revision, cwd=cwd)
      bad_position = source_control.GetCommitTime(bad_revision, cwd=cwd)

    return good_position <= bad_position

  def CanPerformBisect(self, good_revision, bad_revision):
    """Checks whether a given revision is bisectable.

    Checks for following:
    1. Non-bisectable revisions for android bots (refer to crbug.com/385324).
    2. Non-bisectable revisions for Windows bots (refer to crbug.com/405274).

    Args:
      good_revision: Known good revision.
      bad_revision: Known bad revision.

    Returns:
      A dictionary indicating the result. If revision is not bisectable,
      this will contain the field "error", otherwise None.
    """
    if self.opts.target_platform == 'android':
      good_revision = source_control.GetCommitPosition(good_revision)
      if (bisect_utils.IsStringInt(good_revision)
          and good_revision < 265549):
        return {'error': (
            'Bisect cannot continue for the given revision range.\n'
            'It is impossible to bisect Android regressions '
            'prior to r265549, which allows the bisect bot to '
            'rely on Telemetry to do apk installation of the most recently '
            'built local ChromePublic (refer to crbug.com/385324).\n'
            'Please try bisecting revisions greater than or equal to r265549.')}

    if bisect_utils.IsWindowsHost():
      good_revision = source_control.GetCommitPosition(good_revision)
      bad_revision = source_control.GetCommitPosition(bad_revision)
      if (bisect_utils.IsStringInt(good_revision) and
          bisect_utils.IsStringInt(bad_revision)):
        if (289987 <= good_revision < 290716 or
            289987 <= bad_revision < 290716):
          return {'error': ('Oops! Revision between r289987 and r290716 are '
                            'marked as dead zone for Windows due to '
                            'crbug.com/405274. Please try another range.')}

    return None

  def _GatherResultsFromRevertedCulpritCL(
      self, results, target_depot, command_to_run, metric):
    """Gathers performance results with/without culprit CL.

    Attempts to revert the culprit CL against ToT and runs the
    performance tests again with and without the CL, adding the results to
    the over bisect results.

    Args:
      results: BisectResults from the bisect.
      target_depot: The target depot we're bisecting.
      command_to_run: Specify the command to execute the performance test.
      metric: The performance metric to monitor.
    """
    run_results_tot, run_results_reverted = self._RevertCulpritCLAndRetest(
        results, target_depot, command_to_run, metric)

    results.AddRetestResults(run_results_tot, run_results_reverted)

    if len(results.culprit_revisions) != 1:
      return

    # Cleanup reverted files if anything is left.
    _, _, culprit_depot = results.culprit_revisions[0]
    bisect_utils.CheckRunGit(
        ['reset', '--hard', 'HEAD'],
        cwd=self.depot_registry.GetDepotDir(culprit_depot))

  def _RevertCL(self, culprit_revision, culprit_depot):
    """Reverts the specified revision in the specified depot."""
    if self.opts.output_buildbot_annotations:
      bisect_utils.OutputAnnotationStepStart(
          'Reverting culprit CL: %s' % culprit_revision)
    _, return_code = bisect_utils.RunGit(
        ['revert', '--no-commit', culprit_revision],
        cwd=self.depot_registry.GetDepotDir(culprit_depot))
    if return_code:
      bisect_utils.OutputAnnotationStepWarning()
      bisect_utils.OutputAnnotationStepText('Failed to revert CL cleanly.')
    if self.opts.output_buildbot_annotations:
      bisect_utils.OutputAnnotationStepClosed()
    return not return_code

  def _RevertCulpritCLAndRetest(
      self, results, target_depot, command_to_run, metric):
    """Reverts the culprit CL against ToT and runs the performance test.

    Attempts to revert the culprit CL against ToT and runs the
    performance tests again with and without the CL.

    Args:
      results: BisectResults from the bisect.
      target_depot: The target depot we're bisecting.
      command_to_run: Specify the command to execute the performance test.
      metric: The performance metric to monitor.

    Returns:
      A tuple with the results of running the CL at ToT/reverted.
    """
    # Might want to retest ToT with a revert of the CL to confirm that
    # performance returns.
    if results.confidence < bisect_utils.HIGH_CONFIDENCE:
      return (None, None)

    # If there were multiple culprit CLs, we won't try to revert.
    if len(results.culprit_revisions) != 1:
      return (None, None)

    culprit_revision, _, culprit_depot = results.culprit_revisions[0]

    if not self._SyncRevision(target_depot, None, 'gclient'):
      return (None, None)

    head_revision = bisect_utils.CheckRunGit(['log', '--format=%H', '-1'])
    head_revision = head_revision.strip()

    if not self._RevertCL(culprit_revision, culprit_depot):
      return (None, None)

    # If the culprit CL happened to be in a depot that gets pulled in, we
    # can't revert the change and issue a try job to build, since that would
    # require modifying both the DEPS file and files in another depot.
    # Instead, we build locally.
    force_build = (culprit_depot != target_depot)
    if force_build:
      results.warnings.append(
          'Culprit CL is in another depot, attempting to revert and build'
          ' locally to retest. This may not match the performance of official'
          ' builds.')

    run_results_reverted = self._RunTestWithAnnotations(
        'Re-Testing ToT with reverted culprit',
        'Failed to run reverted CL.',
        head_revision, target_depot, command_to_run, metric, force_build)

    # Clear the reverted file(s).
    bisect_utils.RunGit(
        ['reset', '--hard', 'HEAD'],
        cwd=self.depot_registry.GetDepotDir(culprit_depot))

    # Retesting with the reverted CL failed, so bail out of retesting against
    # ToT.
    if run_results_reverted[1]:
      return (None, None)

    run_results_tot = self._RunTestWithAnnotations(
        'Re-Testing ToT',
        'Failed to run ToT.',
        head_revision, target_depot, command_to_run, metric, force_build)

    return (run_results_tot, run_results_reverted)

  def PostBisectResults(self, bisect_results):
    """Posts bisect results to Perf Dashboard."""
    bisect_utils.OutputAnnotationStepStart('Post Results')

    results = bisect_results_json.Get(
        bisect_results, self.opts, self.depot_registry)
    results_json = json.dumps(results)
    data = urllib.urlencode({'data': results_json})
    request = urllib2.Request(PERF_DASH_RESULTS_URL)
    try:
      urllib2.urlopen(request, data)
    except urllib2.URLError as e:
      print 'Failed to post bisect results. Error: %s.' % e
      bisect_utils.OutputAnnotationStepWarning()

    bisect_utils.OutputAnnotationStepClosed()

  def _RunTestWithAnnotations(
      self, step_text, error_text, head_revision,
      target_depot, command_to_run, metric, force_build):
    """Runs the performance test and outputs start/stop annotations.

    Args:
      results: BisectResults from the bisect.
      target_depot: The target depot we're bisecting.
      command_to_run: Specify the command to execute the performance test.
      metric: The performance metric to monitor.
      force_build: Whether to force a build locally.

    Returns:
      Results of the test.
    """
    if self.opts.output_buildbot_annotations:
      bisect_utils.OutputAnnotationStepStart(step_text)

    # Build and run the test again with the reverted culprit CL against ToT.
    run_test_results = self.RunTest(
        head_revision, target_depot, command_to_run,
        metric, skippable=False, skip_sync=True, create_patch=True,
        force_build=force_build)

    if self.opts.output_buildbot_annotations:
      if run_test_results[1]:
        bisect_utils.OutputAnnotationStepWarning()
        bisect_utils.OutputAnnotationStepText(error_text)
      bisect_utils.OutputAnnotationStepClosed()

    return run_test_results

  def Run(self, command_to_run, bad_revision_in, good_revision_in, metric):
    """Given known good and bad revisions, run a binary search on all
    intermediate revisions to determine the CL where the performance regression
    occurred.

    Args:
      command_to_run: Specify the command to execute the performance test.
      good_revision: Number/tag of the known good revision.
      bad_revision: Number/tag of the known bad revision.
      metric: The performance metric to monitor.

    Returns:
      A BisectResults object.
    """
    # Choose depot to bisect first
    target_depot = 'chromium'
    if self.opts.target_platform == 'android-chrome':
      target_depot = 'android-chrome'

    cwd = os.getcwd()
    self.depot_registry.ChangeToDepotDir(target_depot)

    # If they passed SVN revisions, we can try match them to git SHA1 hashes.
    bad_revision = source_control.ResolveToRevision(
        bad_revision_in, target_depot, bisect_utils.DEPOT_DEPS_NAME, 100)
    good_revision = source_control.ResolveToRevision(
        good_revision_in, target_depot, bisect_utils.DEPOT_DEPS_NAME, -100)

    os.chdir(cwd)
    if bad_revision is None:
      return BisectResults(
          error='Couldn\'t resolve [%s] to SHA1.' % bad_revision_in)

    if good_revision is None:
      return BisectResults(
          error='Couldn\'t resolve [%s] to SHA1.' % good_revision_in)

    # Check that they didn't accidentally swap good and bad revisions.
    if not self.CheckIfRevisionsInProperOrder(
        target_depot, good_revision, bad_revision):
      return BisectResults(error='Bad rev (%s) appears to be earlier than good '
                                 'rev (%s).' % (good_revision, bad_revision))

    bad_revision, good_revision = self.NudgeRevisionsIfDEPSChange(
        bad_revision, good_revision, good_revision_in)
    if self.opts.output_buildbot_annotations:
      bisect_utils.OutputAnnotationStepStart('Gathering Revisions')

    cannot_bisect = self.CanPerformBisect(good_revision, bad_revision)
    if cannot_bisect:
      return BisectResults(error=cannot_bisect.get('error'))

    print 'Gathering revision range for bisection.'
    # Retrieve a list of revisions to do bisection on.
    revision_list = self.GetRevisionList(target_depot, bad_revision,
                                         good_revision)

    if self.opts.output_buildbot_annotations:
      bisect_utils.OutputAnnotationStepClosed()

    if revision_list:
      self.PrintRevisionsToBisectMessage(revision_list, target_depot)

      if self.opts.output_buildbot_annotations:
        bisect_utils.OutputAnnotationStepStart('Gathering Reference Values')

      print 'Gathering reference values for bisection.'

      # Perform the performance tests on the good and bad revisions, to get
      # reference values.
      bad_results, good_results = self.GatherReferenceValues(good_revision,
                                                             bad_revision,
                                                             command_to_run,
                                                             metric,
                                                             target_depot)

      if self.opts.output_buildbot_annotations:
        bisect_utils.OutputAnnotationStepClosed()

      if bad_results[1]:
        error = ('An error occurred while building and running the \'bad\' '
                 'reference value. The bisect cannot continue without '
                 'a working \'bad\' revision to start from.\n\nError: %s' %
                 bad_results[0])
        return BisectResults(error=error)

      if good_results[1]:
        error = ('An error occurred while building and running the \'good\' '
                 'reference value. The bisect cannot continue without '
                 'a working \'good\' revision to start from.\n\nError: %s' %
                 good_results[0])
        return BisectResults(error=error)

      # We need these reference values to determine if later runs should be
      # classified as pass or fail.

      known_bad_value = bad_results[0]
      known_good_value = good_results[0]

      # Abort bisect early when the return codes for known good
      # and known bad revisions are same.
      if (self._IsBisectModeReturnCode() and
          known_bad_value['mean'] == known_good_value['mean']):
        return BisectResults(abort_reason=('known good and known bad revisions '
            'returned same return code (return code=%s). '
            'Continuing bisect might not yield any results.' %
            known_bad_value['mean']))
      # Check the direction of improvement only if the improvement_direction
      # option is set to a specific direction (1 for higher is better or -1 for
      # lower is better).
      improvement_dir = self.opts.improvement_direction
      if improvement_dir:
        higher_is_better = improvement_dir > 0
        if higher_is_better:
          message = "Expecting higher values to be better for this metric, "
        else:
          message = "Expecting lower values to be better for this metric, "
        metric_increased = known_bad_value['mean'] > known_good_value['mean']
        if metric_increased:
          message += "and the metric appears to have increased. "
        else:
          message += "and the metric appears to have decreased. "
        if ((higher_is_better and metric_increased) or
            (not higher_is_better and not metric_increased)):
          error = (message + 'Then, the test results for the ends of the given '
                   '\'good\' - \'bad\' range of revisions represent an '
                   'improvement (and not a regression).')
          return BisectResults(error=error)
        logging.info(message + "Therefore we continue to bisect.")

      bisect_state = BisectState(target_depot, revision_list)
      revision_states = bisect_state.GetRevisionStates()

      min_revision = 0
      max_revision = len(revision_states) - 1

      # Can just mark the good and bad revisions explicitly here since we
      # already know the results.
      bad_revision_state = revision_states[min_revision]
      bad_revision_state.external = bad_results[2]
      bad_revision_state.perf_time = bad_results[3]
      bad_revision_state.build_time = bad_results[4]
      bad_revision_state.passed = False
      bad_revision_state.value = known_bad_value

      good_revision_state = revision_states[max_revision]
      good_revision_state.external = good_results[2]
      good_revision_state.perf_time = good_results[3]
      good_revision_state.build_time = good_results[4]
      good_revision_state.passed = True
      good_revision_state.value = known_good_value

      # Check how likely it is that the good and bad results are different
      # beyond chance-induced variation.
      if not (self.opts.debug_ignore_regression_confidence or
              self._IsBisectModeReturnCode()):
        if not _IsRegressionReproduced(known_good_value, known_bad_value,
                                       self.opts.required_initial_confidence):
          # If there is no significant difference between "good" and "bad"
          # revision results, then the "bad revision" is considered "good".
          # TODO(qyearsley): Remove this if it is not necessary.
          bad_revision_state.passed = True
          self.warnings.append(_RegressionNotReproducedWarningMessage(
              good_revision, bad_revision, known_good_value, known_bad_value))
          return BisectResults(bisect_state, self.depot_registry, self.opts,
                               self.warnings)

      while True:
        if not revision_states:
          break

        if max_revision - min_revision <= 1:
          min_revision_state = revision_states[min_revision]
          max_revision_state = revision_states[max_revision]
          current_depot = min_revision_state.depot
          # TODO(sergiyb): Under which conditions can first two branches be hit?
          if min_revision_state.passed == '?':
            next_revision_index = min_revision
          elif max_revision_state.passed == '?':
            next_revision_index = max_revision
          elif current_depot in ['android-chrome', 'chromium', 'v8']:
            previous_revision = revision_states[min_revision].revision
            # If there were changes to any of the external libraries we track,
            # should bisect the changes there as well.
            external_depot = self._FindNextDepotToBisect(
                current_depot, min_revision_state, max_revision_state)
            # If there was no change in any of the external depots, the search
            # is over.
            if not external_depot:
              if current_depot == 'v8':
                self.warnings.append(
                    'Unfortunately, V8 bisection couldn\'t '
                    'continue any further. The script can only bisect into '
                    'V8\'s bleeding_edge repository if both the current and '
                    'previous revisions in trunk map directly to revisions in '
                    'bleeding_edge.')
              break

            earliest_revision = max_revision_state.external[external_depot]
            latest_revision = min_revision_state.external[external_depot]

            new_revision_list = self.PrepareToBisectOnDepot(
                external_depot, earliest_revision, latest_revision,
                previous_revision)

            if not new_revision_list:
              error = ('An error occurred attempting to retrieve revision '
                       'range: [%s..%s]' % (earliest_revision, latest_revision))
              return BisectResults(error=error)

            revision_states = bisect_state.CreateRevisionStatesAfter(
                external_depot, new_revision_list, current_depot,
                previous_revision)

            # Reset the bisection and perform it on the newly inserted states.
            min_revision = 0
            max_revision = len(revision_states) - 1

            print ('Regression in metric %s appears to be the result of '
                   'changes in [%s].' % (metric, external_depot))

            revision_list = [state.revision for state in revision_states]
            self.PrintRevisionsToBisectMessage(revision_list, external_depot)

            continue
          else:
            break
        else:
          next_revision_index = (int((max_revision - min_revision) / 2) +
                                 min_revision)

        next_revision_state = revision_states[next_revision_index]
        next_revision = next_revision_state.revision
        next_depot = next_revision_state.depot

        self.depot_registry.ChangeToDepotDir(next_depot)

        message = 'Working on [%s:%s]' % (next_depot, next_revision)
        print message
        if self.opts.output_buildbot_annotations:
          bisect_utils.OutputAnnotationStepStart(message)

        run_results = self.RunTest(next_revision, next_depot, command_to_run,
                                   metric, skippable=True)

        # If the build is successful, check whether or not the metric
        # had regressed.
        if not run_results[1]:
          if len(run_results) > 2:
            next_revision_state.external = run_results[2]
            next_revision_state.perf_time = run_results[3]
            next_revision_state.build_time = run_results[4]

          passed_regression = self._CheckIfRunPassed(run_results[0],
                                                     known_good_value,
                                                     known_bad_value)

          next_revision_state.passed = passed_regression
          next_revision_state.value = run_results[0]

          if passed_regression:
            max_revision = next_revision_index
          else:
            min_revision = next_revision_index
        else:
          if run_results[1] == BUILD_RESULT_SKIPPED:
            next_revision_state.passed = 'Skipped'
          elif run_results[1] == BUILD_RESULT_FAIL:
            next_revision_state.passed = 'Build Failed'

          print run_results[0]

          # If the build is broken, remove it and redo search.
          revision_states.pop(next_revision_index)

          max_revision -= 1

        if self.opts.output_buildbot_annotations:
          self.printer.PrintPartialResults(bisect_state)
          bisect_utils.OutputAnnotationStepClosed()

      self._ConfidenceExtraTestRuns(min_revision_state, max_revision_state,
                                    command_to_run, metric)
      results = BisectResults(bisect_state, self.depot_registry, self.opts,
                              self.warnings)

      self._GatherResultsFromRevertedCulpritCL(
          results, target_depot, command_to_run, metric)

      return results
    else:
      # Weren't able to sync and retrieve the revision range.
      error = ('An error occurred attempting to retrieve revision range: '
               '[%s..%s]' % (good_revision, bad_revision))
      return BisectResults(error=error)

  def _ConfidenceExtraTestRuns(self, good_state, bad_state, command_to_run,
                               metric):
    if (bool(good_state.passed) != bool(bad_state.passed)
       and good_state.passed not in ('Skipped', 'Build Failed')
       and bad_state.passed not in ('Skipped', 'Build Failed')):
      for state in (good_state, bad_state):
        run_results = self.RunTest(
            state.revision,
            state.depot,
            command_to_run,
            metric,
            test_run_multiplier=BORDER_REVISIONS_EXTRA_RUNS)
        # Is extend the right thing to do here?
        if run_results[1] != BUILD_RESULT_FAIL:
          state.value['values'].extend(run_results[0]['values'])
        else:
          warning_text = 'Re-test of revision %s failed with error message: %s'
          warning_text %= (state.revision, run_results[0])
          if warning_text not in self.warnings:
            self.warnings.append(warning_text)


def _IsPlatformSupported():
  """Checks that this platform and build system are supported.

  Args:
    opts: The options parsed from the command line.

  Returns:
    True if the platform and build system are supported.
  """
  # Haven't tested the script out on any other platforms yet.
  supported = ['posix', 'nt']
  return os.name in supported


def RemoveBuildFiles(build_type):
  """Removes build files from previous runs."""
  out_dir = os.path.join('out', build_type)
  build_dir = os.path.join('build', build_type)
  logging.info('Removing build files in "%s" and "%s".',
               os.path.abspath(out_dir), os.path.abspath(build_dir))
  try:
    RemakeDirectoryTree(out_dir)
    RemakeDirectoryTree(build_dir)
  except Exception as e:
    raise RuntimeError('Got error in RemoveBuildFiles: %s' % e)


def RemakeDirectoryTree(path_to_dir):
  """Removes a directory tree and replaces it with an empty one.

  Returns True if successful, False otherwise.
  """
  RemoveDirectoryTree(path_to_dir)
  MaybeMakeDirectory(path_to_dir)


def RemoveDirectoryTree(path_to_dir):
  """Removes a directory tree. Returns True if successful or False otherwise."""
  if os.path.isfile(path_to_dir):
    logging.info('REMOVING FILE %s' % path_to_dir)
    os.remove(path_to_dir)
  try:
    if os.path.exists(path_to_dir):
      shutil.rmtree(path_to_dir)
  except OSError, e:
    if e.errno != errno.ENOENT:
      raise


# This is copied from build/scripts/common/chromium_utils.py.
def MaybeMakeDirectory(*path):
  """Creates an entire path, if it doesn't already exist."""
  file_path = os.path.join(*path)
  try:
    os.makedirs(file_path)
  except OSError as e:
    if e.errno != errno.EEXIST:
      raise


class BisectOptions(object):
  """Options to be used when running bisection."""
  def __init__(self):
    super(BisectOptions, self).__init__()

    self.target_platform = 'chromium'
    self.build_preference = None
    self.good_revision = None
    self.bad_revision = None
    self.use_goma = None
    self.goma_dir = None
    self.goma_threads = 64
    self.repeat_test_count = 20
    self.truncate_percent = 25
    self.max_time_minutes = 20
    self.metric = None
    self.command = None
    self.output_buildbot_annotations = None
    self.no_custom_deps = False
    self.working_directory = None
    self.extra_src = None
    self.debug_ignore_build = None
    self.debug_ignore_sync = None
    self.debug_ignore_perf_test = None
    self.debug_ignore_regression_confidence = None
    self.debug_fake_first_test_mean = 0
    self.target_arch = 'ia32'
    self.target_build_type = 'Release'
    self.builder_type = 'perf'
    self.bisect_mode = bisect_utils.BISECT_MODE_MEAN
    self.improvement_direction = 0
    self.bug_id = ''
    self.required_initial_confidence = 80.0
    self.try_job_id = None

  @staticmethod
  def _AddBisectOptionsGroup(parser):
    group = parser.add_argument_group('Bisect options')
    group.add_argument('-c', '--command', required=True,
                       help='A command to execute your performance test at '
                            'each point in the bisection.')
    group.add_argument('-b', '--bad_revision', required=True,
                       help='A bad revision to start bisection. Must be later '
                            'than good revision. May be either a git or svn '
                            'revision.')
    group.add_argument('-g', '--good_revision', required=True,
                       help='A revision to start bisection where performance '
                            'test is known to pass. Must be earlier than the '
                            'bad revision. May be either a git or a svn '
                            'revision.')
    group.add_argument('-m', '--metric',
                       help='The desired metric to bisect on. For example '
                            '"vm_rss_final_b/vm_rss_f_b"')
    group.add_argument('-d', '--improvement_direction', type=int, default=0,
                       help='An integer number representing the direction of '
                            'improvement. 1 for higher is better, -1 for lower '
                            'is better, 0 for ignore (default).')
    group.add_argument('-r', '--repeat_test_count', type=int, default=20,
                       choices=range(1, 101),
                       help='The number of times to repeat the performance '
                            'test. Values will be clamped to range [1, 100]. '
                            'Default value is 20.')
    group.add_argument('--max_time_minutes', type=int, default=20,
                       choices=range(1, 61),
                       help='The maximum time (in minutes) to take running the '
                            'performance tests. The script will run the '
                            'performance tests according to '
                            '--repeat_test_count, so long as it doesn\'t exceed'
                            ' --max_time_minutes. Values will be clamped to '
                            'range [1, 60]. Default value is 20.')
    group.add_argument('-t', '--truncate_percent', type=int, default=25,
                       help='The highest/lowest percent are discarded to form '
                            'a truncated mean. Values will be clamped to range '
                            '[0, 25]. Default value is 25 percent.')
    group.add_argument('--bisect_mode', default=bisect_utils.BISECT_MODE_MEAN,
                       choices=[bisect_utils.BISECT_MODE_MEAN,
                                bisect_utils.BISECT_MODE_STD_DEV,
                                bisect_utils.BISECT_MODE_RETURN_CODE],
                       help='The bisect mode. Choices are to bisect on the '
                            'difference in mean, std_dev, or return_code.')
    group.add_argument('--bug_id', default='',
                       help='The id for the bug associated with this bisect. ' +
                            'If this number is given, bisect will attempt to ' +
                            'verify that the bug is not closed before '
                            'starting.')
    group.add_argument('--try_job_id', default=None,
                       help='The id assigned by Perf Dashboard when sending ' +
                            'try jobs.')
    group.add_argument('--required_initial_confidence', type=float,
                       default=80.0,
                       help='The required confidence score for the initial '
                            'check to see whether there is a significant '
                            'difference between given good and bad revisions.')

  @staticmethod
  def _AddBuildOptionsGroup(parser):
    group = parser.add_argument_group('Build options')
    group.add_argument('-w', '--working_directory',
                       help='Path to the working directory where the script '
                       'will do an initial checkout of the chromium depot. The '
                       'files will be placed in a subdirectory "bisect" under '
                       'working_directory and that will be used to perform the '
                       'bisection. This parameter is optional, if it is not '
                       'supplied, the script will work from the current depot.')
    group.add_argument('--build_preference',
                       choices=['msvs', 'ninja', 'make'],
                       help='The preferred build system to use. On linux/mac '
                            'the options are make/ninja. On Windows, the '
                            'options are msvs/ninja.')
    group.add_argument('--target_platform', default='chromium',
                       choices=['chromium', 'android', 'android-chrome'],
                       help='The target platform. Choices are "chromium" '
                            '(current platform), or "android". If you specify '
                            'something other than "chromium", you must be '
                            'properly set up to build that platform.')
    group.add_argument('--no_custom_deps', dest='no_custom_deps',
                       action='store_true', default=False,
                       help='Run the script with custom_deps or not.')
    group.add_argument('--extra_src',
                       help='Path to a script which can be used to modify the '
                            'bisect script\'s behavior.')
    group.add_argument('--use_goma', action='store_true',
                       help='Add a bunch of extra threads for goma, and enable '
                            'goma')
    group.add_argument('--goma_dir',
                       help='Path to goma tools (or system default if not '
                            'specified).')
    group.add_argument('--goma_threads', type=int, default='64',
                       help='Number of threads for goma, only if using goma.')
    group.add_argument('--output_buildbot_annotations', action='store_true',
                       help='Add extra annotation output for buildbot.')
    group.add_argument('--target_arch', default='ia32',
                       dest='target_arch',
                       choices=['ia32', 'x64', 'arm', 'arm64'],
                       help='The target build architecture. Choices are "ia32" '
                            '(default), "x64", "arm" or "arm64".')
    group.add_argument('--target_build_type', default='Release',
                       choices=['Release', 'Debug', 'Release_x64'],
                       help='The target build type. Choices are "Release" '
                            '(default), Release_x64 or "Debug".')
    group.add_argument('--builder_type', default=fetch_build.PERF_BUILDER,
                       choices=[fetch_build.PERF_BUILDER,
                                fetch_build.FULL_BUILDER,
                                fetch_build.ANDROID_CHROME_PERF_BUILDER, ''],
                       help='Type of builder to get build from. This '
                            'determines both the bot that builds and the '
                            'place where archived builds are downloaded from. '
                            'For local builds, an empty string can be passed.')

  @staticmethod
  def _AddDebugOptionsGroup(parser):
    group = parser.add_argument_group('Debug options')
    group.add_argument('--debug_ignore_build', action='store_true',
                       help='DEBUG: Don\'t perform builds.')
    group.add_argument('--debug_ignore_sync', action='store_true',
                       help='DEBUG: Don\'t perform syncs.')
    group.add_argument('--debug_ignore_perf_test', action='store_true',
                       help='DEBUG: Don\'t perform performance tests.')
    group.add_argument('--debug_ignore_regression_confidence',
                       action='store_true',
                       help='DEBUG: Don\'t score the confidence of the initial '
                            'good and bad revisions\' test results.')
    group.add_argument('--debug_fake_first_test_mean', type=int, default='0',
                       help='DEBUG: When faking performance tests, return this '
                            'value as the mean of the first performance test, '
                            'and return a mean of 0.0 for further tests.')
    return group

  @classmethod
  def _CreateCommandLineParser(cls):
    """Creates a parser with bisect options.

    Returns:
      An instance of argparse.ArgumentParser.
    """
    usage = ('%(prog)s [options] [-- chromium-options]\n'
             'Perform binary search on revision history to find a minimal '
             'range of revisions where a performance metric regressed.\n')

    parser = argparse.ArgumentParser(usage=usage)
    cls._AddBisectOptionsGroup(parser)
    cls._AddBuildOptionsGroup(parser)
    cls._AddDebugOptionsGroup(parser)
    return parser

  def ParseCommandLine(self):
    """Parses the command line for bisect options."""
    parser = self._CreateCommandLineParser()
    opts = parser.parse_args()

    try:
      if (not opts.metric and
          opts.bisect_mode != bisect_utils.BISECT_MODE_RETURN_CODE):
        raise RuntimeError('missing required parameter: --metric')

      if opts.bisect_mode != bisect_utils.BISECT_MODE_RETURN_CODE:
        metric_values = opts.metric.split('/')
        if len(metric_values) != 2:
          raise RuntimeError('Invalid metric specified: [%s]' % opts.metric)
        opts.metric = metric_values

      opts.truncate_percent = min(max(opts.truncate_percent, 0), 25) / 100.0

      for k, v in opts.__dict__.iteritems():
        assert hasattr(self, k), 'Invalid %s attribute in BisectOptions.' % k
        setattr(self, k, v)
    except RuntimeError, e:
      output_string = StringIO.StringIO()
      parser.print_help(file=output_string)
      error_message = '%s\n\n%s' % (e.message, output_string.getvalue())
      output_string.close()
      raise RuntimeError(error_message)

  @staticmethod
  def FromDict(values):
    """Creates an instance of BisectOptions from a dictionary.

    Args:
      values: a dict containing options to set.

    Returns:
      An instance of BisectOptions.
    """
    opts = BisectOptions()
    for k, v in values.iteritems():
      assert hasattr(opts, k), 'Invalid %s attribute in BisectOptions.' % k
      setattr(opts, k, v)

    if opts.metric and opts.bisect_mode != bisect_utils.BISECT_MODE_RETURN_CODE:
      metric_values = opts.metric.split('/')
      if len(metric_values) != 2:
        raise RuntimeError('Invalid metric specified: [%s]' % opts.metric)
      opts.metric = metric_values

    if opts.target_arch == 'x64' and opts.target_build_type == 'Release':
      opts.target_build_type = 'Release_x64'
    opts.repeat_test_count = min(max(opts.repeat_test_count, 1), 100)
    opts.max_time_minutes = min(max(opts.max_time_minutes, 1), 60)
    opts.truncate_percent = min(max(opts.truncate_percent, 0), 25)
    opts.truncate_percent = opts.truncate_percent / 100.0

    return opts


def _ConfigureLogging():
  """Trivial logging config.

  Configures logging to output any messages at or above INFO to standard out,
  without any additional formatting.
  """
  logging_format = '%(message)s'
  logging.basicConfig(
      stream=logging.sys.stdout, level=logging.INFO, format=logging_format)


def main():
  _ConfigureLogging()
  try:
    opts = BisectOptions()
    opts.ParseCommandLine()

    if opts.bug_id:
      if opts.output_buildbot_annotations:
        bisect_utils.OutputAnnotationStepStart('Checking Issue Tracker')
      issue_closed = query_crbug.CheckIssueClosed(opts.bug_id)
      if issue_closed:
        print 'Aborting bisect because bug is closed'
      else:
        print 'Could not confirm bug is closed, proceeding.'
      if opts.output_buildbot_annotations:
        bisect_utils.OutputAnnotationStepClosed()
      if issue_closed:
        results = BisectResults(abort_reason='the bug is closed.')
        bisect_printer = BisectPrinter(opts)
        bisect_printer.FormatAndPrintResults(results)
        return 0

    if opts.extra_src:
      extra_src = bisect_utils.LoadExtraSrc(opts.extra_src)
      if not extra_src:
        raise RuntimeError('Invalid or missing --extra_src.')
      bisect_utils.AddAdditionalDepotInfo(extra_src.GetAdditionalDepotInfo())

    if opts.working_directory:
      custom_deps = bisect_utils.DEFAULT_GCLIENT_CUSTOM_DEPS
      if opts.no_custom_deps:
        custom_deps = None
      bisect_utils.CreateBisectDirectoryAndSetupDepot(opts, custom_deps)

      os.chdir(os.path.join(os.getcwd(), 'src'))
      RemoveBuildFiles(opts.target_build_type)

    if not _IsPlatformSupported():
      raise RuntimeError('Sorry, this platform isn\'t supported yet.')

    if not source_control.IsInGitRepository():
      raise RuntimeError(
          'Sorry, only the git workflow is supported at the moment.')

    # gClient sync seems to fail if you're not in master branch.
    if (not source_control.IsInProperBranch() and
        not opts.debug_ignore_sync and
        not opts.working_directory):
      raise RuntimeError('You must switch to master branch to run bisection.')
    bisect_test = BisectPerformanceMetrics(opts, os.getcwd())
    try:
      results = bisect_test.Run(opts.command, opts.bad_revision,
                                opts.good_revision, opts.metric)
      if results.error:
        raise RuntimeError(results.error)
      bisect_test.printer.FormatAndPrintResults(results)
      bisect_test.PostBisectResults(results)
      return 0
    finally:
      bisect_test.PerformCleanup()
  except RuntimeError as e:
    if opts.output_buildbot_annotations:
      # The perf dashboard scrapes the "results" step in order to comment on
      # bugs. If you change this, please update the perf dashboard as well.
      bisect_utils.OutputAnnotationStepStart('Results')
    print 'Runtime Error: %s' % e
    if opts.output_buildbot_annotations:
      bisect_utils.OutputAnnotationStepClosed()
  return 1


if __name__ == '__main__':
  sys.exit(main())
