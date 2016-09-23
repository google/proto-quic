# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""This file contains printing-related functionality of the bisect."""

import datetime
import re

from bisect_results import BisectResults
import bisect_utils
import source_control


# The perf dashboard looks for a string like "Estimated Confidence: 95%"
# to decide whether or not to cc the author(s). If you change this, please
# update the perf dashboard as well.
RESULTS_BANNER = """
===== BISECT JOB RESULTS =====
Status: %(status)s

Test Command: %(command)s
Test Metric: %(metric)s
Relative Change: %(change)s
Estimated Confidence: %(confidence).02f%%
Retested CL with revert: %(retest)s"""

# When the bisect was aborted without a bisect failure the following template
# is used.
ABORT_REASON_TEMPLATE = """
===== BISECTION ABORTED =====
The bisect was aborted because %(abort_reason)s
Please contact the the team (see below) if you believe this is in error.

Bug ID: %(bug_id)s

Test Command: %(command)s
Test Metric: %(metric)s
Good revision: %(good_revision)s
Bad revision: %(bad_revision)s """

# The perf dashboard specifically looks for the string
# "Author  : " to parse out who to cc on a bug. If you change the
# formatting here, please update the perf dashboard as well.
RESULTS_REVISION_INFO = """
===== SUSPECTED CL(s) =====
Subject : %(subject)s
Author  : %(author)s%(commit_info)s
Commit  : %(cl)s
Date    : %(cl_date)s"""

RESULTS_THANKYOU = """
| O O | Visit http://www.chromium.org/developers/speed-infra/perf-bug-faq
|  X  | for more information addressing perf regression bugs. For feedback,
| / \\ | file a bug with label Cr-Tests-AutoBisect.  Thank you!"""


class BisectPrinter(object):

  def __init__(self, opts, depot_registry=None):
    self.opts = opts
    self.depot_registry = depot_registry

  def FormatAndPrintResults(self, bisect_results):
    """Prints the results from a bisection run in a readable format.

    Also prints annotations creating buildbot step "Results".

    Args:
      bisect_results: BisectResult object containing results to be printed.
    """
    if bisect_results.abort_reason:
      self._PrintAbortResults(bisect_results.abort_reason)
      return

    if self.opts.output_buildbot_annotations:
      bisect_utils.OutputAnnotationStepStart('Build Status Per Revision')

    print
    print 'Full results of bisection:'
    for revision_state in bisect_results.state.GetRevisionStates():
      build_status = revision_state.passed

      if type(build_status) is bool:
        if build_status:
          build_status = 'Good'
        else:
          build_status = 'Bad'

      print '  %20s  %40s  %s' % (revision_state.depot,
                                  revision_state.revision,
                                  build_status)
    print

    if self.opts.output_buildbot_annotations:
      bisect_utils.OutputAnnotationStepClosed()
      # The perf dashboard scrapes the "results" step in order to comment on
      # bugs. If you change this, please update the perf dashboard as well.
      bisect_utils.OutputAnnotationStepStart('Results')

    self._PrintBanner(bisect_results)
    self._PrintWarnings(bisect_results.warnings)

    if bisect_results.culprit_revisions and bisect_results.confidence:
      for culprit in bisect_results.culprit_revisions:
        cl, info, depot = culprit
        self._PrintRevisionInfo(cl, info, depot)
    self._PrintRetestResults(bisect_results)
    self._PrintTestedCommitsTable(bisect_results.state.GetRevisionStates(),
                                  bisect_results.first_working_revision,
                                  bisect_results.last_broken_revision,
                                  bisect_results.confidence,
                                  final_step=True)
    self._PrintStepTime(bisect_results.state.GetRevisionStates())
    self._PrintThankYou()
    if self.opts.output_buildbot_annotations:
      bisect_utils.OutputAnnotationStepClosed()

  def PrintPartialResults(self, bisect_state):
    revision_states = bisect_state.GetRevisionStates()
    first_working_rev, last_broken_rev = BisectResults.FindBreakingRevRange(
        revision_states)
    self._PrintTestedCommitsTable(revision_states, first_working_rev,
                                  last_broken_rev, 100, final_step=False)

  def _PrintAbortResults(self, abort_reason):
    if self.opts.output_buildbot_annotations:
      bisect_utils.OutputAnnotationStepStart('Results')

    # Metric string in config is not split in case of return code mode.
    if (self.opts.metric and
        self.opts.bisect_mode != bisect_utils.BISECT_MODE_RETURN_CODE):
      metric = '/'.join(self.opts.metric)
    else:
      metric = self.opts.metric

    print ABORT_REASON_TEMPLATE % {
        'abort_reason': abort_reason,
        'bug_id': self.opts.bug_id or 'NOT SPECIFIED',
        'command': self.opts.command,
        'metric': metric,
        'good_revision': self.opts.good_revision,
        'bad_revision': self.opts.bad_revision,
    }
    self._PrintThankYou()
    if self.opts.output_buildbot_annotations:
      bisect_utils.OutputAnnotationStepClosed()

  @staticmethod
  def _PrintThankYou():
    print RESULTS_THANKYOU

  @staticmethod
  def _PrintStepTime(revision_states):
    """Prints information about how long various steps took.

    Args:
      revision_states: Ordered list of revision states."""
    step_perf_time_avg = 0.0
    step_build_time_avg = 0.0
    step_count = 0.0
    for revision_state in revision_states:
      if revision_state.value:
        step_perf_time_avg += revision_state.perf_time
        step_build_time_avg += revision_state.build_time
        step_count += 1
    if step_count:
      step_perf_time_avg = step_perf_time_avg / step_count
      step_build_time_avg = step_build_time_avg / step_count
    print
    print 'Average build time : %s' % datetime.timedelta(
        seconds=int(step_build_time_avg))
    print 'Average test time  : %s' % datetime.timedelta(
        seconds=int(step_perf_time_avg))

  @staticmethod
  def _GetViewVCLinkFromDepotAndHash(git_revision, depot):
    """Gets link to the repository browser."""
    if depot and 'viewvc' in bisect_utils.DEPOT_DEPS_NAME[depot]:
      return bisect_utils.DEPOT_DEPS_NAME[depot]['viewvc'] + git_revision
    return ''

  def _PrintRevisionInfo(self, cl, info, depot=None):
    commit_link = self._GetViewVCLinkFromDepotAndHash(cl, depot)
    if commit_link:
      commit_link = '\nLink    : %s' % commit_link
    else:
      commit_link = ('\Description:\n%s' % info['body'])
    print RESULTS_REVISION_INFO % {
        'subject': info['subject'],
        'author': info['email'],
        'commit_info': commit_link,
        'cl': cl,
        'cl_date': info['date']
    }

  @staticmethod
  def _PrintTableRow(column_widths, row_data):
    """Prints out a row in a formatted table that has columns aligned.

    Args:
      column_widths: A list of column width numbers.
      row_data: A list of items for each column in this row.
    """
    assert len(column_widths) == len(row_data)
    text = ''
    for i in xrange(len(column_widths)):
      current_row_data = row_data[i].center(column_widths[i], ' ')
      text += ('%%%ds' % column_widths[i]) % current_row_data
    print text

  def _PrintTestedCommitsHeader(self):
    if self.opts.bisect_mode == bisect_utils.BISECT_MODE_MEAN:
      self._PrintTableRow(
          [20, 12, 70, 14, 12, 13],
          ['Depot', 'Position', 'SHA', 'Mean', 'Std. Error', 'State'])
    elif self.opts.bisect_mode == bisect_utils.BISECT_MODE_STD_DEV:
      self._PrintTableRow(
          [20, 12, 70, 14, 12, 13],
          ['Depot', 'Position', 'SHA', 'Std. Error', 'Mean', 'State'])
    elif self.opts.bisect_mode == bisect_utils.BISECT_MODE_RETURN_CODE:
      self._PrintTableRow(
          [20, 12, 70, 14, 13],
          ['Depot', 'Position', 'SHA', 'Return Code', 'State'])
    else:
      assert False, 'Invalid bisect_mode specified.'

  def _PrintTestedCommitsEntry(self, revision_state, commit_position, cl_link,
                               state_str):
    if self.opts.bisect_mode == bisect_utils.BISECT_MODE_MEAN:
      std_error = '+-%.02f' % revision_state.value['std_err']
      mean = '%.02f' % revision_state.value['mean']
      self._PrintTableRow(
          [20, 12, 70, 12, 14, 13],
          [revision_state.depot, commit_position, cl_link, mean, std_error,
           state_str])
    elif self.opts.bisect_mode == bisect_utils.BISECT_MODE_STD_DEV:
      std_error = '+-%.02f' % revision_state.value['std_err']
      mean = '%.02f' % revision_state.value['mean']
      self._PrintTableRow(
          [20, 12, 70, 12, 14, 13],
          [revision_state.depot, commit_position, cl_link, std_error, mean,
           state_str])
    elif self.opts.bisect_mode == bisect_utils.BISECT_MODE_RETURN_CODE:
      mean = '%d' % revision_state.value['mean']
      self._PrintTableRow(
          [20, 12, 70, 14, 13],
          [revision_state.depot, commit_position, cl_link, mean,
           state_str])

  def _PrintTestedCommitsTable(
      self, revision_states, first_working_revision, last_broken_revision,
      confidence, final_step=True):
    print
    if final_step:
      print '===== TESTED COMMITS ====='
    else:
      print '===== PARTIAL RESULTS ====='
    self._PrintTestedCommitsHeader()
    state = 0
    for revision_state in revision_states:
      if revision_state.value:
        if (revision_state == last_broken_revision or
            revision_state == first_working_revision):
          # If confidence is too low, don't add this empty line since it's
          # used to put focus on a suspected CL.
          if confidence and final_step:
            print
          state += 1
          if state == 2 and not final_step:
            # Just want a separation between "bad" and "good" cl's.
            print

        state_str = 'Bad'
        if state == 1 and final_step:
          state_str = 'Suspected CL'
        elif state == 2:
          state_str = 'Good'

        # If confidence is too low, don't bother outputting good/bad.
        if not confidence:
          state_str = ''
        state_str = state_str.center(13, ' ')
        commit_position = source_control.GetCommitPosition(
            revision_state.revision,
            self.depot_registry.GetDepotDir(revision_state.depot))
        display_commit_pos = ''
        if commit_position:
          display_commit_pos = str(commit_position)
        self._PrintTestedCommitsEntry(revision_state,
                                      display_commit_pos,
                                      revision_state.revision,
                                      state_str)

  def _PrintRetestResults(self, bisect_results):
    if (not bisect_results.retest_results_tot or
        not bisect_results.retest_results_reverted):
      return
    print
    print '===== RETEST RESULTS ====='
    self._PrintTestedCommitsEntry(
        bisect_results.retest_results_tot, '', '', '')
    self._PrintTestedCommitsEntry(
        bisect_results.retest_results_reverted, '', '', '')

  def _PrintBanner(self, bisect_results):
    if self.opts.bisect_mode == bisect_utils.BISECT_MODE_RETURN_CODE:
      metric = 'N/A'
      change = 'Yes'
    else:
      metric = '/'.join(self.opts.metric)
      change = '%.02f%% (+/-%.02f%%)' % (
          bisect_results.regression_size, bisect_results.regression_std_err)
    if not bisect_results.culprit_revisions:
      change = 'No significant change reproduced.'

    print RESULTS_BANNER % {
        'status': self._StatusMessage(bisect_results),
        'command': self.opts.command,
        'metric': metric,
        'change': change,
        'confidence': bisect_results.confidence,
        'retest': 'Yes' if bisect_results.retest_results_tot else 'No',
    }

  @staticmethod
  def _StatusMessage(bisect_results):
    if bisect_results.confidence >= bisect_utils.HIGH_CONFIDENCE:
      return 'Positive: Reproduced a change.'
    elif bisect_results.culprit_revisions:
      return 'Negative: Found possible suspect(s), but with low confidence.'
    return 'Negative: Did not reproduce a change.'

  @staticmethod
  def _PrintWarnings(warnings):
    """Prints a list of warning strings if there are any."""
    if not warnings:
      return
    print
    print 'WARNINGS:'
    for w in set(warnings):
      print '  ! %s' % w
