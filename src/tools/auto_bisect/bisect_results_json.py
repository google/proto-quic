# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os

import bisect_utils
import source_control


def Get(bisect_results, opts, depot_registry):
  """Returns the results as a jsonable object."""
  if opts.bisect_mode == bisect_utils.BISECT_MODE_RETURN_CODE:
    change = '0'
  else:
    metric = '/'.join(opts.metric)
    change = '%.02f%%' % bisect_results.regression_size

  status = 'completed'

  return {
      'try_job_id': opts.try_job_id,
      'bug_id': opts.bug_id,
      'status': status,
      'buildbot_log_url': _GetBuildBotLogUrl(),
      'bisect_bot': os.environ.get('BUILDBOT_BUILDERNAME', ''),
      'command': opts.command,
      'metric': metric,
      'change': change,
      'score': bisect_results.confidence,
      'good_revision': opts.good_revision,
      'bad_revision': opts.bad_revision,
      'warnings': bisect_results.warnings,
      'abort_reason': bisect_results.abort_reason,
      'culprit_data': _CulpritData(bisect_results),
      'revision_data': _RevisionData(bisect_results, depot_registry),
  }


def _CulpritData(bisect_results):
  if not bisect_results.culprit_revisions:
    return None
  cl, culprit_info, depot = bisect_results.culprit_revisions[0]
  commit_link = _GetViewVCLinkFromDepotAndHash(cl, depot)
  if commit_link:
    commit_link = '\nLink    : %s' % commit_link
  else:
    commit_link = ('\Description:\n%s' % culprit_info['body'])

  return {
      'subject': culprit_info['subject'],
      'author': culprit_info['email'],
      'email': culprit_info['email'],
      'cl_date': culprit_info['date'],
      'commit_info': commit_link,
      'revisions_links': [],
      'cl': cl
  }


def _RevisionData(bisect_results, depot_registry):
  revision_rows = []
  for state in bisect_results.state.GetRevisionStates():
    commit_position = source_control.GetCommitPosition(
        state.revision, depot_registry.GetDepotDir(state.depot))
    revision_rows.append({
        'depot_name': state.depot,
        'deps_revision': state.revision,
        'commit_pos': commit_position,
        'result': 'good' if state.passed else 'bad',
    })
  return revision_rows


def _GetViewVCLinkFromDepotAndHash(git_revision, depot):
  """Gets link to the repository browser."""
  if depot and 'viewvc' in bisect_utils.DEPOT_DEPS_NAME[depot]:
    return bisect_utils.DEPOT_DEPS_NAME[depot]['viewvc'] + git_revision
  return ''


def _GetBuildBotLogUrl():
  master_url = os.environ.get('BUILDBOT_BUILDBOTURL')
  builder_name = os.environ.get('BUILDBOT_BUILDERNAME')
  builder_number = os.environ.get('BUILDBOT_BUILDNUMBER')
  if master_url and builder_name and builder_number:
    return '%s%s/%s' % (master_url, builder_name, builder_number)
  return ''
