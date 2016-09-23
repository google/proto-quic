# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import json
import os
import re
import shutil
import sys
import urlparse
import unittest

SRC = os.path.join(os.path.dirname(__file__), os.path.pardir, os.path.pardir)
sys.path.append(os.path.join(SRC, 'third_party', 'pymock'))

import bisect_perf_regression
import bisect_results
import bisect_state
import bisect_utils
import fetch_build
import mock
import source_control


# Regression confidence: 0%
CLEAR_NON_REGRESSION = [
    # Mean: 30.223 Std. Dev.: 11.383
    [[16.886], [16.909], [16.99], [17.723], [17.952], [18.118], [19.028],
     [19.552], [21.954], [38.573], [38.839], [38.965], [40.007], [40.572],
     [41.491], [42.002], [42.33], [43.109], [43.238]],
    # Mean: 34.76 Std. Dev.: 11.516
    [[16.426], [17.347], [20.593], [21.177], [22.791], [27.843], [28.383],
     [28.46], [29.143], [40.058], [40.303], [40.558], [41.918], [42.44],
     [45.223], [46.494], [50.002], [50.625], [50.839]]
]

# Regression confidence: ~ 90%
ALMOST_REGRESSION = [
    # Mean: 30.042 Std. Dev.: 2.002
    [[26.146], [28.04], [28.053], [28.074], [28.168], [28.209], [28.471],
     [28.652], [28.664], [30.862], [30.973], [31.002], [31.897], [31.929],
     [31.99], [32.214], [32.323], [32.452], [32.696]],
    # Mean: 33.008 Std. Dev.: 4.265
    [[34.963], [30.741], [39.677], [39.512], [34.314], [31.39], [34.361],
     [25.2], [30.489], [29.434]]
]

# Regression confidence: ~ 98%
BARELY_REGRESSION = [
    # Mean: 28.828 Std. Dev.: 1.993
    [[26.96], [27.605], [27.768], [27.829], [28.006], [28.206], [28.393],
     [28.911], [28.933], [30.38], [30.462], [30.808], [31.74], [31.805],
     [31.899], [32.077], [32.454], [32.597], [33.155]],
    # Mean: 31.156 Std. Dev.: 1.980
    [[28.729], [29.112], [29.258], [29.454], [29.789], [30.036], [30.098],
     [30.174], [30.534], [32.285], [32.295], [32.552], [32.572], [32.967],
     [33.165], [33.403], [33.588], [33.744], [34.147], [35.84]]
]

# Regression confidence: 99.5%
CLEAR_REGRESSION = [
    # Mean: 30.254 Std. Dev.: 2.987
    [[26.494], [26.621], [26.701], [26.997], [26.997], [27.05], [27.37],
     [27.488], [27.556], [31.846], [32.192], [32.21], [32.586], [32.596],
     [32.618], [32.95], [32.979], [33.421], [33.457], [34.97]],
    # Mean: 33.190 Std. Dev.: 2.972
    [[29.547], [29.713], [29.835], [30.132], [30.132], [30.33], [30.406],
     [30.592], [30.72], [34.486], [35.247], [35.253], [35.335], [35.378],
     [35.934], [36.233], [36.41], [36.947], [37.982]]
]

# Regression confidence > 95%, taken from: crbug.com/434318
# Specifically from Builder android_nexus10_perf_bisect Build #1198
MULTIPLE_VALUES = [
    [
        [18.916, 22.371, 8.527, 5.877, 5.407, 9.476, 8.100, 5.334,
         4.507, 4.842, 8.485, 8.308, 27.490, 4.560, 4.804, 23.068, 17.577,
         17.346, 26.738, 60.330, 32.307, 5.468, 27.803, 27.373, 17.823,
         5.158, 27.439, 5.236, 11.413],
        [18.999, 22.642, 8.158, 5.995, 5.495, 9.499, 8.092, 5.324,
         4.468, 4.788, 8.248, 7.853, 27.533, 4.410, 4.622, 22.341, 22.313,
         17.072, 26.731, 57.513, 33.001, 5.500, 28.297, 27.277, 26.462,
         5.009, 27.361, 5.130, 10.955]
    ],
    [
        [18.238, 22.365, 8.555, 5.939, 5.437, 9.463, 7.047, 5.345, 4.517,
         4.796, 8.593, 7.901, 27.499, 4.378, 5.040, 4.904, 4.816, 4.828,
         4.853, 57.363, 34.184, 5.482, 28.190, 27.290, 26.694, 5.099,
         4.905, 5.290, 4.813],
        [18.301, 22.522, 8.035, 6.021, 5.565, 9.037, 6.998, 5.321, 4.485,
         4.768, 8.397, 7.865, 27.636, 4.640, 5.015, 4.962, 4.933, 4.977,
         4.961, 60.648, 34.593, 5.538, 28.454, 27.297, 26.490, 5.099, 5,
         5.247, 4.945],
        [18.907, 23.368, 8.100, 6.169, 5.621, 9.971, 8.161, 5.331, 4.513,
         4.837, 8.255, 7.852, 26.209, 4.388, 5.045, 5.029, 5.032, 4.946,
         4.973, 60.334, 33.377, 5.499, 28.275, 27.550, 26.103, 5.108,
         4.951, 5.285, 4.910],
        [18.715, 23.748, 8.128, 6.148, 5.691, 9.361, 8.106, 5.334, 4.528,
         4.965, 8.261, 7.851, 27.282, 4.391, 4.949, 4.981, 4.964, 4.935,
         4.933, 60.231, 33.361, 5.489, 28.106, 27.457, 26.648, 5.108,
         4.963, 5.272, 4.954]
    ]
]

# Default options for the dry run
DEFAULT_OPTIONS = {
    'debug_ignore_build': True,
    'debug_ignore_sync': True,
    'debug_ignore_perf_test': True,
    'debug_ignore_regression_confidence': True,
    'command': 'fake_command',
    'metric': 'fake/metric',
    'good_revision': 280000,
    'bad_revision': 280005,
}

# This global is a placeholder for a generator to be defined by the test cases
# that use _MockRunTests.
_MockResultsGenerator = (x for x in [])

def _MakeMockRunTests(bisect_mode_is_return_code=False):
  def _MockRunTests(*args, **kwargs):  # pylint: disable=unused-argument
    return _FakeTestResult(
        _MockResultsGenerator.next(), bisect_mode_is_return_code)

  return _MockRunTests


def _FakeTestResult(values, bisect_mode_is_return_code):
  mean = 0.0
  if bisect_mode_is_return_code:
    mean = 0 if (all(v == 0 for v in values)) else 1
  result_dict = {'mean': mean, 'std_err': 0.0, 'std_dev': 0.0, 'values': values}
  success_code = 0
  return (result_dict, success_code)


def _SampleBisecResult(opts):
  revisions = [
      'ae7ef14ba2d9b5ef0d2c1c092ec98a417e44740d'
      'ab55ead638496b061c9de61685b982f7cea38ca7',
      '89aa0c99e4b977b9a4f992ac14da0d6624f7316e']
  state = bisect_state.BisectState(depot='chromium', revisions=revisions)
  depot_registry = bisect_perf_regression.DepotDirectoryRegistry('/mock/src')
  results = bisect_results.BisectResults(
      bisect_state=state, depot_registry=depot_registry, opts=opts,
      runtime_warnings=[])
  results.confidence = 99.9
  results.culprit_revisions = [(
      'ab55ead638496b061c9de61685b982f7cea38ca7',
      {
          'date': 'Thu, 26 Jun 2014 14:29:49 +0000',
          'body': 'Fix',
          'author': 'author@chromium.org',
          'subject': 'Fix',
          'email': 'author@chromium.org',
      },
      'chromium')]
  return results


def _GetMockCallArg(function_mock, call_index):
  """Gets the list of called arguments for call at |call_index|.

  Args:
    function_mock: A Mock object.
    call_index: The index at which the mocked function was called.

  Returns:
    The called argument list.
  """
  call_args_list = function_mock.call_args_list
  if not call_args_list or len(call_args_list) <= call_index:
    return None
  args, _ = call_args_list[call_index]
  return args


def _GetBisectPerformanceMetricsInstance(options_dict):
  """Returns an instance of the BisectPerformanceMetrics class."""
  opts = bisect_perf_regression.BisectOptions.FromDict(options_dict)
  return bisect_perf_regression.BisectPerformanceMetrics(opts, os.getcwd())


def _GetExtendedOptions(improvement_dir, fake_first, ignore_confidence=True,
                        **extra_opts):
  """Returns the a copy of the default options dict plus some options."""
  result = dict(DEFAULT_OPTIONS)
  result.update({
      'improvement_direction': improvement_dir,
      'debug_fake_first_test_mean': fake_first,
      'debug_ignore_regression_confidence': ignore_confidence
  })
  result.update(extra_opts)
  return result


def _GenericDryRun(options, print_results=False):
  """Performs a dry run of the bisector.

  Args:
    options: Dictionary containing the options for the bisect instance.
    print_results: Boolean telling whether to call FormatAndPrintResults.

  Returns:
    The results dictionary as returned by the bisect Run method.
  """
  _AbortIfThereAreStagedChanges()
  # Disable rmtree to avoid deleting local trees.
  old_rmtree = shutil.rmtree
  shutil.rmtree = lambda path, on_error: None
  # git reset HEAD may be run during the dry run, which removes staged changes.
  try:
    bisect_instance = _GetBisectPerformanceMetricsInstance(options)
    results = bisect_instance.Run(
        bisect_instance.opts.command, bisect_instance.opts.bad_revision,
        bisect_instance.opts.good_revision, bisect_instance.opts.metric)

    if print_results:
      bisect_instance.printer.FormatAndPrintResults(results)

    return results
  finally:
    shutil.rmtree = old_rmtree


def _AbortIfThereAreStagedChanges():
  """Exits the test prematurely if there are staged changes."""
  # The output of "git status --short" will be an empty string if there are
  # no staged changes in the current branch. Untracked files are ignored
  # because when running the presubmit on the trybot there are sometimes
  # untracked changes to the run-perf-test.cfg and bisect.cfg files.
  status_output = bisect_utils.CheckRunGit(
      ['status', '--short', '--untracked-files=no'])
  if status_output:
    print 'There are un-committed changes in the current branch.'
    print 'Aborting the tests to avoid destroying local changes. Changes:'
    print status_output
    sys.exit(1)


class BisectPerfRegressionTest(unittest.TestCase):
  """Test case for other functions and classes in bisect-perf-regression.py."""

  def setUp(self):
    self.cwd = os.getcwd()
    os.chdir(os.path.abspath(os.path.join(os.path.dirname(__file__),
                                          os.path.pardir, os.path.pardir)))

  def tearDown(self):
    os.chdir(self.cwd)

  def testBisectOptionsCanPrintHelp(self):
    """Tests that the argument parser can be made and can print help."""
    bisect_options = bisect_perf_regression.BisectOptions()
    parser = bisect_options._CreateCommandLineParser()
    parser.format_help()

  def testParseDEPSStringManually(self):
    """Tests DEPS parsing."""
    deps_file_contents = """
    vars = {
        'ffmpeg_hash':
             '@ac4a9f31fe2610bd146857bbd55d7a260003a888',
        'webkit_url':
             'https://chromium.googlesource.com/chromium/blink.git',
        'git_url':
             'https://chromium.googlesource.com',
        'webkit_rev':
             '@e01ac0a267d1017288bc67fa3c366b10469d8a24',
        'angle_revision':
             '74697cf2064c0a2c0d7e1b1b28db439286766a05'
    }"""

    # Should only expect SVN/git revisions to come through, and URLs should be
    # filtered out.
    expected_vars_dict = {
        'ffmpeg_hash': '@ac4a9f31fe2610bd146857bbd55d7a260003a888',
        'webkit_rev': '@e01ac0a267d1017288bc67fa3c366b10469d8a24',
        'angle_revision': '74697cf2064c0a2c0d7e1b1b28db439286766a05'
    }
    # Testing private function.
    # pylint: disable=W0212
    vars_dict = bisect_perf_regression._ParseRevisionsFromDEPSFileManually(
        deps_file_contents)
    self.assertEqual(vars_dict, expected_vars_dict)

  def _AssertParseResult(self, expected_values, result_string):
    """Asserts some values are parsed from a RESULT line."""
    results_template = ('RESULT other_chart: other_trace= 123 count\n'
                        'RESULT my_chart: my_trace= %(value)s\n')
    results = results_template % {'value': result_string}
    metric = ['my_chart', 'my_trace']
    # Testing private function.
    # pylint: disable=W0212
    values = bisect_perf_regression._TryParseResultValuesFromOutput(
        metric, results)
    self.assertEqual(expected_values, values)

  def testTryParseResultValuesFromOutput_WithSingleValue(self):
    """Tests result pattern <*>RESULT <graph>: <trace>= <value>"""
    self._AssertParseResult([66.88], '66.88 kb')
    self._AssertParseResult([66.88], '66.88 ')
    self._AssertParseResult([-66.88], '-66.88 kb')
    self._AssertParseResult([66], '66 kb')
    self._AssertParseResult([0.66], '.66 kb')
    self._AssertParseResult([], '. kb')
    self._AssertParseResult([], 'aaa kb')

  def testTryParseResultValuesFromOutput_WithMultiValue(self):
    """Tests result pattern <*>RESULT <graph>: <trace>= [<value>,<value>, ..]"""
    self._AssertParseResult([66.88], '[66.88] kb')
    self._AssertParseResult([66.88, 99.44], '[66.88, 99.44]kb')
    self._AssertParseResult([66.88, 99.44], '[ 66.88, 99.44 ]')
    self._AssertParseResult([-66.88, 99.44], '[-66.88, 99.44] kb')
    self._AssertParseResult([-66, 99], '[-66,99] kb')
    self._AssertParseResult([-66, 99], '[-66,99,] kb')
    self._AssertParseResult([-66, 0.99], '[-66,.99] kb')
    self._AssertParseResult([], '[] kb')
    self._AssertParseResult([], '[-66,abc] kb')

  def testTryParseResultValuesFromOutputWithMeanStd(self):
    """Tests result pattern <*>RESULT <graph>: <trace>= {<mean, std}"""
    self._AssertParseResult([33.22], '{33.22, 3.6} kb')
    self._AssertParseResult([33.22], '{33.22, 3.6} kb')
    self._AssertParseResult([33.22], '{33.22,3.6}kb')
    self._AssertParseResult([33.22], '{33.22,3.6} kb')
    self._AssertParseResult([33.22], '{ 33.22,3.6 }kb')
    self._AssertParseResult([-33.22], '{-33.22,3.6}kb')
    self._AssertParseResult([22], '{22,6}kb')
    self._AssertParseResult([.22], '{.22,6}kb')
    self._AssertParseResult([], '{.22,6, 44}kb')
    self._AssertParseResult([], '{}kb')
    self._AssertParseResult([], '{XYZ}kb')

  # This method doesn't reference self; it fails if an error is thrown.
  # pylint: disable=R0201
  def testDryRun(self):
    """Does a dry run of the bisect script.

    This serves as a smoke test to catch errors in the basic execution of the
    script.
    """
    _GenericDryRun(DEFAULT_OPTIONS, True)

  def testBisectImprovementDirectionFails(self):
    """Dry run of a bisect with an improvement instead of regression."""
    # Test result goes from 0 to 100 where higher is better
    results = _GenericDryRun(_GetExtendedOptions(1, 100))
    self.assertIsNotNone(results.error)
    self.assertIn('not a regression', results.error)

    # Test result goes from 0 to -100 where lower is better
    results = _GenericDryRun(_GetExtendedOptions(-1, -100))
    self.assertIsNotNone(results.error)
    self.assertIn('not a regression', results.error)

  def testBisectImprovementDirectionSucceeds(self):
    """Bisects with improvement direction matching regression range."""
    # Test result goes from 0 to 100 where lower is better
    results = _GenericDryRun(_GetExtendedOptions(-1, 100))
    self.assertIsNone(results.error)
    # Test result goes from 0 to -100 where higher is better
    results = _GenericDryRun(_GetExtendedOptions(1, -100))
    self.assertIsNone(results.error)

  @mock.patch('urllib2.urlopen')
  def testBisectResultsPosted(self, mock_urlopen):
    options_dict = dict(DEFAULT_OPTIONS)
    options_dict.update({
        'bisect_mode': bisect_utils.BISECT_MODE_MEAN,
        'try_job_id': 1234,
    })
    opts = bisect_perf_regression.BisectOptions.FromDict(options_dict)
    bisect_instance = _GetBisectPerformanceMetricsInstance(options_dict)
    results = _SampleBisecResult(opts)
    bisect_instance.PostBisectResults(results)

    call_args = _GetMockCallArg(mock_urlopen, 0)
    self.assertIsNotNone(call_args)
    called_data = urlparse.parse_qs(call_args[1])
    results_data = json.loads(called_data['data'][0])
    self.assertEqual(1234, results_data['try_job_id'])

  def _CheckAbortsEarly(self, results, **extra_opts):
    """Returns True if the bisect job would abort early."""
    global _MockResultsGenerator
    _MockResultsGenerator = (r for r in results)
    bisect_class = bisect_perf_regression.BisectPerformanceMetrics
    original_run_tests = bisect_class.RunPerformanceTestAndParseResults
    bisect_class.RunPerformanceTestAndParseResults = _MakeMockRunTests()

    try:
      dry_run_results = _GenericDryRun(_GetExtendedOptions(
          improvement_dir=0, fake_first=0, ignore_confidence=False,
          **extra_opts))
    except StopIteration:
      # If StopIteration was raised, that means that the next value after
      # the first two values was requested, so the job was not aborted.
      return False
    finally:
      bisect_class.RunPerformanceTestAndParseResults = original_run_tests

    # If the job was aborted, there should be a warning about it.
    self.assertTrue(
        any('did not clearly reproduce a regression' in w
            for w in dry_run_results.warnings))
    return True

  def testBisectAbortedOnClearNonRegression(self):
    self.assertTrue(self._CheckAbortsEarly(CLEAR_NON_REGRESSION))

  def testBisectNotAborted_AlmostRegression(self):
    self.assertFalse(self._CheckAbortsEarly(ALMOST_REGRESSION))

  def testBisectNotAborted_ClearRegression(self):
    self.assertFalse(self._CheckAbortsEarly(CLEAR_REGRESSION))

  def testBisectNotAborted_BarelyRegression(self):
    self.assertFalse(self._CheckAbortsEarly(BARELY_REGRESSION))

  def testBisectNotAborted_MultipleValues(self):
    self.assertFalse(self._CheckAbortsEarly(MULTIPLE_VALUES))

  def testBisectNotAbortedWhenRequiredConfidenceIsZero(self):
    self.assertFalse(self._CheckAbortsEarly(
        CLEAR_NON_REGRESSION, required_initial_confidence=0))

  def _CheckAbortsEarlyForReturnCode(self, results):
    """Returns True if the bisect job would abort early in return code mode."""
    global _MockResultsGenerator
    _MockResultsGenerator = (r for r in results)
    bisect_class = bisect_perf_regression.BisectPerformanceMetrics
    original_run_tests = bisect_class.RunPerformanceTestAndParseResults
    bisect_class.RunPerformanceTestAndParseResults = _MakeMockRunTests(True)
    options = dict(DEFAULT_OPTIONS)
    options.update({'bisect_mode': 'return_code'})
    try:
      dry_run_results = _GenericDryRun(options)
    except StopIteration:
      # If StopIteration was raised, that means that the next value after
      # the first two values was requested, so the job was not aborted.
      return False
    finally:
      bisect_class.RunPerformanceTestAndParseResults = original_run_tests

    # If the job was aborted, there should be a warning about it.
    if ('known good and known bad revisions returned same' in
        dry_run_results.abort_reason):
      return True
    return False

  def testBisectAbortOn_SameReturnCode(self):
    self.assertTrue(self._CheckAbortsEarlyForReturnCode([[0,0,0], [0,0,0]]))

  def testBisectNotAbortedOn_DifferentReturnCode(self):
    self.assertFalse(self._CheckAbortsEarlyForReturnCode([[1,1,1], [0,0,0]]))

  def testGetCommitPosition(self):
    cp_git_rev = '7017a81991de983e12ab50dfc071c70e06979531'
    self.assertEqual(291765, source_control.GetCommitPosition(cp_git_rev))

    svn_git_rev = 'e6db23a037cad47299a94b155b95eebd1ee61a58'
    self.assertEqual(291467, source_control.GetCommitPosition(svn_git_rev))

  def testGetCommitPositionForV8(self):
    bisect_instance = _GetBisectPerformanceMetricsInstance(DEFAULT_OPTIONS)
    v8_rev = '21d700eedcdd6570eff22ece724b63a5eefe78cb'
    depot_path = os.path.join(bisect_instance.src_cwd, 'v8')
    self.assertEqual(
        23634, source_control.GetCommitPosition(v8_rev, depot_path))

  def testGetCommitPositionForSkia(self):
    bisect_instance = _GetBisectPerformanceMetricsInstance(DEFAULT_OPTIONS)
    skia_rev = 'a94d028eCheckAbortsEarly0f2c77f159b3dac95eb90c3b4cf48c61'
    depot_path = os.path.join(bisect_instance.src_cwd, 'third_party', 'skia')
    # Skia doesn't use commit positions, and GetCommitPosition should
    # return None for repos that don't use commit positions.
    self.assertIsNone(source_control.GetCommitPosition(skia_rev, depot_path))

  def testUpdateDepsContent(self):
    bisect_instance = _GetBisectPerformanceMetricsInstance(DEFAULT_OPTIONS)
    deps_file = 'DEPS'
    # We are intentionally reading DEPS file contents instead of string literal
    # with few lines from DEPS because to check if the format we are expecting
    # to search is not changed in DEPS content.
    # TODO (prasadv): Add a separate test to validate the DEPS contents with the
    # format that bisect script expects.
    deps_contents = bisect_perf_regression.ReadStringFromFile(deps_file)
    deps_key = 'v8_revision'
    depot = 'v8'
    git_revision = 'a12345789a23456789a123456789a123456789'
    updated_content = bisect_instance.UpdateDepsContents(
        deps_contents, depot, git_revision, deps_key)
    self.assertIsNotNone(updated_content)
    ss = re.compile('["\']%s["\']: ["\']%s["\']' % (deps_key, git_revision))
    self.assertIsNotNone(re.search(ss, updated_content))

  @mock.patch('bisect_utils.RunGClient')
  def testSyncToRevisionForChromium(self, mock_RunGClient):
    bisect_instance = _GetBisectPerformanceMetricsInstance(DEFAULT_OPTIONS)
    mock_RunGClient.return_value = 0
    bisect_instance._SyncRevision(
        'chromium', 'e6db23a037cad47299a94b155b95eebd1ee61a58', 'gclient')
    expected_params = [
        'sync',
        '--verbose',
        '--nohooks',
        '--force',
        '--delete_unversioned_trees',
        '--revision',
        'src@e6db23a037cad47299a94b155b95eebd1ee61a58',
    ]

    mock_RunGClient.assert_called_with(expected_params, cwd=None)

  @mock.patch('bisect_utils.RunGit')
  def testSyncToRevisionForWebKit(self, mock_RunGit):
    bisect_instance = _GetBisectPerformanceMetricsInstance(DEFAULT_OPTIONS)
    mock_RunGit.return_value = None, None
    bisect_instance._SyncRevision(
        'webkit', 'a94d028e0f2c77f159b3dac95eb90c3b4cf48c61', None)
    expected_params = ['checkout', 'a94d028e0f2c77f159b3dac95eb90c3b4cf48c61']
    mock_RunGit.assert_called_with(expected_params)

  def testTryJobSvnRepo_PerfBuilderType_ReturnsRepoUrl(self):
    self.assertEqual(
        bisect_perf_regression.PERF_SVN_REPO_URL,
        bisect_perf_regression._TryJobSvnRepo(fetch_build.PERF_BUILDER))

  def testTryJobSvnRepo_FullBuilderType_ReturnsRepoUrl(self):
    self.assertEqual(
        bisect_perf_regression.FULL_SVN_REPO_URL,
        bisect_perf_regression._TryJobSvnRepo(fetch_build.FULL_BUILDER))

  def testTryJobSvnRepo_WithUnknownBuilderType_ThrowsError(self):
    with self.assertRaises(NotImplementedError):
      bisect_perf_regression._TryJobSvnRepo('foo')

  def _CheckIsDownloadable(self, depot, target_platform='chromium',
                           builder_type='perf'):
    opts = dict(DEFAULT_OPTIONS)
    opts.update({'target_platform': target_platform,
                 'builder_type': builder_type})
    bisect_instance = _GetBisectPerformanceMetricsInstance(opts)
    return bisect_instance.IsDownloadable(depot)

  def testIsDownloadable_ChromiumDepot_ReturnsTrue(self):
    self.assertTrue(self._CheckIsDownloadable(depot='chromium'))

  def testIsDownloadable_DEPSDepot_ReturnsTrue(self):
    self.assertTrue(self._CheckIsDownloadable(depot='v8'))

  def testIsDownloadable_AndroidChromeDepot_ReturnsTrue(self):
    self.assertTrue(self._CheckIsDownloadable(
        depot='android-chrome', target_platform='android-chrome'))

  def testIsDownloadable_AndroidChromeWithDEPSChromium_ReturnsFalse(self):
    self.assertFalse(self._CheckIsDownloadable(
        depot='chromium', target_platform='android-chrome'))

  def testIsDownloadable_AndroidChromeWithDEPSV8_ReturnsFalse(self):
    self.assertFalse(self._CheckIsDownloadable(
        depot='v8', target_platform='android-chrome'))

  def testIsDownloadable_NoBuilderType_ReturnsFalse(self):
    self.assertFalse(
        self._CheckIsDownloadable(depot='chromium', builder_type=''))


class DepotDirectoryRegistryTest(unittest.TestCase):

  def setUp(self):
    self.old_chdir = os.chdir
    os.chdir = self.mockChdir
    self.old_depot_names = bisect_utils.DEPOT_NAMES
    bisect_utils.DEPOT_NAMES = ['mock_depot']
    self.old_depot_deps_name = bisect_utils.DEPOT_DEPS_NAME
    bisect_utils.DEPOT_DEPS_NAME = {'mock_depot': {'src': 'src/foo'}}

    self.registry = bisect_perf_regression.DepotDirectoryRegistry('/mock/src')
    self.cur_dir = None

  def tearDown(self):
    os.chdir = self.old_chdir
    bisect_utils.DEPOT_NAMES = self.old_depot_names
    bisect_utils.DEPOT_DEPS_NAME = self.old_depot_deps_name

  def mockChdir(self, new_dir):
    self.cur_dir = new_dir

  def testReturnsCorrectResultForChrome(self):
    self.assertEqual(self.registry.GetDepotDir('chromium'), '/mock/src')

  def testUsesDepotSpecToInitializeRegistry(self):
    self.assertEqual(self.registry.GetDepotDir('mock_depot'), '/mock/src/foo')

  def testChangedTheDirectory(self):
    self.registry.ChangeToDepotDir('mock_depot')
    self.assertEqual(self.cur_dir, '/mock/src/foo')


# The tests below test private functions (W0212).
# pylint: disable=W0212
class GitTryJobTestCases(unittest.TestCase):

  """Test case for bisect try job."""
  def setUp(self):
    bisect_utils_patcher = mock.patch('bisect_perf_regression.bisect_utils')
    self.mock_bisect_utils = bisect_utils_patcher.start()
    self.addCleanup(bisect_utils_patcher.stop)

  def _SetupRunGitMock(self, git_cmds):
    """Setup RunGit mock with expected output for given git command."""
    def side_effect(git_cmd_args):
      for val in git_cmds:
        if set(val[0]) == set(git_cmd_args):
          return val[1]
    self.mock_bisect_utils.RunGit = mock.Mock(side_effect=side_effect)

  def _AssertRunGitExceptions(self, git_cmds, func, *args):
    """Setup RunGit mock and tests RunGitException.

    Args:
      git_cmds: List of tuples with git command and expected output.
      func: Callback function to be executed.
      args: List of arguments to be passed to the function.
    """
    self._SetupRunGitMock(git_cmds)
    self.assertRaises(bisect_perf_regression.RunGitError,
                      func,
                      *args)

  def testNotGitRepo(self):
    new_branch = bisect_perf_regression.BISECT_TRYJOB_BRANCH
    parent_branch = bisect_perf_regression.BISECT_MASTER_BRANCH
    cmds = [(['rev-parse', '--abbrev-ref', 'HEAD'], (None, 128))]
    self._AssertRunGitExceptions(cmds,
                                 bisect_perf_regression._PrepareBisectBranch,
                                 parent_branch, new_branch)

  def testFailedCheckoutMaster(self):
    new_branch = bisect_perf_regression.BISECT_TRYJOB_BRANCH
    parent_branch = bisect_perf_regression.BISECT_MASTER_BRANCH
    cmds = [
        (['rev-parse', '--abbrev-ref', 'HEAD'], (new_branch, 0)),
        (['checkout', '-f', parent_branch], ('Checkout Failed', 1)),
    ]
    self._AssertRunGitExceptions(cmds,
                                 bisect_perf_regression._PrepareBisectBranch,
                                 parent_branch, new_branch)

  def testDeleteBisectBranchIfExists(self):
    new_branch = bisect_perf_regression.BISECT_TRYJOB_BRANCH
    parent_branch = bisect_perf_regression.BISECT_MASTER_BRANCH
    cmds = [
        (['rev-parse', '--abbrev-ref', 'HEAD'], (parent_branch, 0)),
        (['branch', '--list'], ('bisect-tryjob\n*master\nsomebranch', 0)),
        (['branch', '-D', new_branch], ('Failed to delete branch', 128)),
    ]
    self._AssertRunGitExceptions(cmds,
                                 bisect_perf_regression._PrepareBisectBranch,
                                 parent_branch, new_branch)

  def testCreatNewBranchFails(self):
    new_branch = bisect_perf_regression.BISECT_TRYJOB_BRANCH
    parent_branch = bisect_perf_regression.BISECT_MASTER_BRANCH
    cmds = [
        (['rev-parse', '--abbrev-ref', 'HEAD'], (parent_branch, 0)),
        (['branch', '--list'], ('bisect-tryjob\n*master\nsomebranch', 0)),
        (['branch', '-D', new_branch], ('None', 0)),
        (['update-index', '--refresh', '-q'], (None, 0)),
        (['diff-index', 'HEAD'], (None, 0)),
        (['checkout', '-b', new_branch], ('Failed to create branch', 128)),
    ]
    self._AssertRunGitExceptions(cmds,
                                 bisect_perf_regression._PrepareBisectBranch,
                                 parent_branch, new_branch)

  def testSetUpstreamToFails(self):
    new_branch = bisect_perf_regression.BISECT_TRYJOB_BRANCH
    parent_branch = bisect_perf_regression.BISECT_MASTER_BRANCH
    cmds = [
        (['rev-parse', '--abbrev-ref', 'HEAD'], (parent_branch, 0)),
        (['branch', '--list'], ('bisect-tryjob\n*master\nsomebranch', 0)),
        (['branch', '-D', new_branch], ('None', 0)),
        (['update-index', '--refresh', '-q'], (None, 0)),
        (['diff-index', 'HEAD'], (None, 0)),
        (['checkout', '-b', new_branch], ('None', 0)),
        (['branch', '--set-upstream-to', parent_branch],
         ('Setuptream fails', 1)),
    ]
    self._AssertRunGitExceptions(cmds,
                                 bisect_perf_regression._PrepareBisectBranch,
                                 parent_branch, new_branch)

  def testStartBuilderTryJobForException(self):
    git_revision = 'ac4a9f31fe2610bd146857bbd55d7a260003a888'
    bot_name = 'linux_perf_bisect_builder'
    bisect_job_name = 'testBisectJobname'
    patch = None
    patch_content = '/dev/null'
    new_branch = bisect_perf_regression.BISECT_TRYJOB_BRANCH
    parent_branch = bisect_perf_regression.BISECT_MASTER_BRANCH
    try_cmd = [
        (['rev-parse', '--abbrev-ref', 'HEAD'], (parent_branch, 0)),
        (['branch', '--list'], ('bisect-tryjob\n*master\nsomebranch', 0)),
        (['branch', '-D', new_branch], ('None', 0)),
        (['update-index', '--refresh', '-q'], (None, 0)),
        (['diff-index', 'HEAD'], (None, 0)),
        (['checkout', '-b', new_branch], ('None', 0)),
        (['branch', '--set-upstream-to', parent_branch],
         ('Setuptream fails', 0)),
        (['try',
          '--bot=%s' % bot_name,
          '--revision=%s' % git_revision,
          '--name=%s' % bisect_job_name,
          '--svn_repo=%s' % bisect_perf_regression.PERF_SVN_REPO_URL,
          '--diff=%s' % patch_content],
         (None, 1)),
    ]
    self._AssertRunGitExceptions(
        try_cmd, bisect_perf_regression._StartBuilderTryJob,
        fetch_build.PERF_BUILDER, git_revision, bot_name, bisect_job_name,
        patch)

  def testBuilderTryJob(self):
    git_revision = 'ac4a9f31fe2610bd146857bbd55d7a260003a888'
    bot_name = 'linux_perf_bisect_builder'
    bisect_job_name = 'testBisectJobname'
    patch = None
    patch_content = '/dev/null'
    new_branch = bisect_perf_regression.BISECT_TRYJOB_BRANCH
    parent_branch = bisect_perf_regression.BISECT_MASTER_BRANCH
    try_cmd = [
        (['rev-parse', '--abbrev-ref', 'HEAD'], (parent_branch, 0)),
        (['branch', '--list'], ('bisect-tryjob\n*master\nsomebranch', 0)),
        (['branch', '-D', new_branch], ('None', 0)),
        (['update-index', '--refresh', '-q'], (None, 0)),
        (['diff-index', 'HEAD'], (None, 0)),
        (['checkout', '-b', new_branch], ('None', 0)),
        (['branch', '--set-upstream-to', parent_branch],
         ('Setuptream fails', 0)),
        (['try',
          '--bot=%s' % bot_name,
          '--revision=%s' % git_revision,
          '--name=%s' % bisect_job_name,
          '--svn_repo=%s' % bisect_perf_regression.PERF_SVN_REPO_URL,
          '--diff=%s' % patch_content],
         (None, 0)),
    ]
    self._SetupRunGitMock(try_cmd)
    bisect_perf_regression._StartBuilderTryJob(
        fetch_build.PERF_BUILDER, git_revision, bot_name, bisect_job_name,
        patch)


if __name__ == '__main__':
  unittest.main()
