# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import math
import os

import bisect_utils
import math_utils
import source_control
import ttest

from bisect_state import RevisionState


class BisectResults(object):
  """Contains results of the completed bisect.

  Properties:
    error: Error message if the bisect failed.

  If the error is None, the following properties are present:
    warnings: List of warnings from the bisect run.
    state: BisectState object from which these results were generated.
    first_working_revision: First good revision.
    last_broken_revision: Last bad revision.

  If both of above revisions are not None, the follow properties are present:
    culprit_revisions: A list of revisions, which contain the bad change
        introducing the failure.
    regression_size: For performance bisects, this is a relative change of
        the mean metric value. For other bisects this field always contains
        'zero-to-nonzero'.
    regression_std_err: For performance bisects, it is a pooled standard error
        for groups of good and bad runs. Not used for other bisects.
    confidence: For performance bisects, it is a confidence that the good and
        bad runs are distinct groups. Not used for non-performance bisects.
  """

  def __init__(self, bisect_state=None, depot_registry=None, opts=None,
               runtime_warnings=None, error=None, abort_reason=None):
    """Computes final bisect results after a bisect run is complete.

    This constructor should be called in one of the following ways:
      BisectResults(state, depot_registry, opts, runtime_warnings)
      BisectResults(error=error)

    First option creates an object representing successful bisect results, while
    second option creates an error result.

    Args:
      bisect_state: BisectState object representing latest bisect state.
      depot_registry: DepotDirectoryRegistry object with information on each
          repository in the bisect_state.
      opts: Options passed to the bisect run.
      runtime_warnings: A list of warnings from the bisect run.
      error: Error message. When error is not None, other arguments are ignored.
    """
    # Setting these attributes so that bisect printer does not break when the
    # regression cannot be reproduced (no broken revision was found)
    self.regression_size = 0
    self.regression_std_err = 0
    self.confidence = 0
    self.culprit_revisions = []

    self.error = error
    self.abort_reason = abort_reason
    if error is not None or abort_reason is not None:
      return

    assert (bisect_state is not None and depot_registry is not None and
            opts is not None and runtime_warnings is not None), (
                'Incorrect use of the BisectResults constructor. '
                'When error is None, all other arguments are required.')

    self.state = bisect_state

    rev_states = bisect_state.GetRevisionStates()
    first_working_rev, last_broken_rev = self.FindBreakingRevRange(rev_states)
    self.first_working_revision = first_working_rev
    self.last_broken_revision = last_broken_rev

    self.warnings = runtime_warnings

    self.retest_results_tot = None
    self.retest_results_reverted = None

    if first_working_rev is not None and last_broken_rev is not None:
      statistics = self._ComputeRegressionStatistics(
          rev_states, first_working_rev, last_broken_rev)

      self.regression_size = statistics['regression_size']
      self.regression_std_err = statistics['regression_std_err']
      self.confidence = statistics['confidence']

      self.culprit_revisions = self._FindCulpritRevisions(
          rev_states, depot_registry, first_working_rev, last_broken_rev)

      self.warnings += self._GetResultBasedWarnings(
          self.culprit_revisions, opts, self.confidence)

  def AddRetestResults(self, results_tot, results_reverted):
    if not results_tot or not results_reverted:
      self.warnings.append(
          'Failed to re-test reverted culprit CL against ToT.')
      return

    confidence = BisectResults.ConfidenceScore(
        results_reverted[0]['values'],
        results_tot[0]['values'])

    self.retest_results_tot = RevisionState('ToT', 'n/a', 0)
    self.retest_results_tot.value = results_tot[0]

    self.retest_results_reverted = RevisionState('Reverted', 'n/a', 0)
    self.retest_results_reverted.value = results_reverted[0]

    if confidence <= bisect_utils.HIGH_CONFIDENCE:
      self.warnings.append(
          'Confidence of re-test with reverted CL is not high.'
          ' Check that the regression hasn\'t already recovered. '
          ' There\'s still a chance this is a regression, as performance of'
          ' local builds may not match official builds.')

  @staticmethod
  def _GetResultBasedWarnings(culprit_revisions, opts, confidence):
    warnings = []
    if len(culprit_revisions) > 1:
      warnings.append('Due to build errors, regression range could '
                      'not be narrowed down to a single commit.')
    if opts.repeat_test_count == 1:
      warnings.append('Tests were only set to run once. This may '
                      'be insufficient to get meaningful results.')
    if 0 < confidence < bisect_utils.HIGH_CONFIDENCE:
      warnings.append('Confidence is not high. Try bisecting again '
                      'with increased repeat_count, larger range, or '
                      'on another metric.')
    if not confidence:
      warnings.append('Confidence score is 0%. Try bisecting again on '
                      'another platform or another metric.')
    return warnings

  @staticmethod
  def ConfidenceScore(sample1, sample2, accept_single_bad_or_good=False):
    """Calculates a confidence score.

    This score is based on a statistical hypothesis test. The null
    hypothesis is that the two groups of results have no difference,
    i.e. there is no performance regression. The alternative hypothesis
    is that there is some difference between the groups that's unlikely
    to occur by chance.

    The score returned by this function represents our confidence in the
    alternative hypothesis.

    Note that if there's only one item in either sample, this means only
    one revision was classified good or bad, so there's not much evidence
    to make a decision.

    Args:
      sample1: A flat list of "good" result numbers.
      sample2: A flat list of "bad" result numbers.
      accept_single_bad_or_good: If True, compute a value even if
          there is only one bad or good revision.

    Returns:
      A float between 0 and 100; 0 if the samples aren't large enough.
    """
    if ((len(sample1) <= 1 or len(sample2) <= 1) and
        not accept_single_bad_or_good):
      return 0.0
    if not sample1 or not sample2:
      return 0.0
    _, _, p_value = ttest.WelchsTTest(sample1, sample2)
    return 100.0 * (1.0 - p_value)

  @staticmethod
  def FindBreakingRevRange(revision_states):
    """Finds the last known good and first known bad revisions.

    Note that since revision_states is expected to be in reverse chronological
    order, the last known good revision is the first revision in the list that
    has the passed property set to 1, therefore the name
    `first_working_revision`. The inverse applies to `last_broken_revision`.

    Args:
      revision_states: A list of RevisionState instances.

    Returns:
      A tuple containing the two revision states at the border. (Last
      known good and first known bad.)
    """
    first_working_revision = None
    last_broken_revision = None

    for revision_state in revision_states:
      if revision_state.passed == 1 and not first_working_revision:
        first_working_revision = revision_state

      if not revision_state.passed:
        last_broken_revision = revision_state

    return first_working_revision, last_broken_revision

  @staticmethod
  def _FindCulpritRevisions(revision_states, depot_registry, first_working_rev,
                            last_broken_rev):
    cwd = os.getcwd()

    culprit_revisions = []
    for i in xrange(last_broken_rev.index, first_working_rev.index):
      depot_registry.ChangeToDepotDir(revision_states[i].depot)
      info = source_control.QueryRevisionInfo(revision_states[i].revision)
      culprit_revisions.append((revision_states[i].revision, info,
                                revision_states[i].depot))

    os.chdir(cwd)
    return culprit_revisions

  @classmethod
  def _ComputeRegressionStatistics(cls, rev_states, first_working_rev,
                                   last_broken_rev):
    # TODO(sergiyb): We assume that value has "values" key, which may not be
    # the case for failure-bisects, where there is a single value only.
    broken_means = [state.value['values']
                    for state in rev_states[:last_broken_rev.index+1]
                    if state.value]

    working_means = [state.value['values']
                     for state in rev_states[first_working_rev.index:]
                     if state.value]

    # Flatten the lists to calculate mean of all values.
    working_mean = sum(working_means, [])
    broken_mean = sum(broken_means, [])

    # Calculate the approximate size of the regression
    mean_of_bad_runs = math_utils.Mean(broken_mean)
    mean_of_good_runs = math_utils.Mean(working_mean)

    regression_size = 100 * math_utils.RelativeChange(mean_of_good_runs,
                                                      mean_of_bad_runs)
    if math.isnan(regression_size):
      regression_size = 'zero-to-nonzero'

    regression_std_err = math.fabs(math_utils.PooledStandardError(
        [working_mean, broken_mean]) /
        max(0.0001, min(mean_of_good_runs, mean_of_bad_runs))) * 100.0

    # Give a "confidence" in the bisect culprit by seeing whether the results
    # of the culprit revision and the revision before that appear to be
    # statistically significantly different.
    confidence = cls.ConfidenceScore(
        sum([first_working_rev.value['values']], []),
        sum([last_broken_rev.value['values']], []))

    bad_greater_than_good = mean_of_bad_runs > mean_of_good_runs

    return {'regression_size': regression_size,
            'regression_std_err': regression_std_err,
            'confidence': confidence,
            'bad_greater_than_good': bad_greater_than_good}
