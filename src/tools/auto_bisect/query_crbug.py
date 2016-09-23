# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Utility functions to query the chromium issue tracker.

Note that documentation for the Issue Tracker API says it's DEPRECATED, however
it seems to be in use in other places like the performance dashboard. Also,
this module attempts to handle most exceptions thrown by querying the tracker
so that when and if this api is turned off no impact is caused to the bisection
process."""

import json
import urllib2

SINGLE_ISSUE_URL = ('https://code.google.com/feeds/issues/p/chromium/issues'
                    '/full?id=%s&alt=json')


class IssueTrackerQueryException(Exception):
  pass


def QuerySingleIssue(issue_id, url_template=SINGLE_ISSUE_URL):
  """Queries the tracker for a specific issue. Returns a dict.

  This uses the deprecated Issue Tracker API to fetch a JSON representation of
  the issue details.

  Args:
    issue_id: An int or string representing the issue id.
    url_template: URL to query the tracker with '%s' instead of the bug id.

  Returns:
    A dictionary as parsed by the JSON library from the tracker response.

  Raises:
    urllib2.HTTPError when appropriate.
  """
  assert str(issue_id).isdigit()
  response = urllib2.urlopen(url_template % issue_id).read()
  return json.loads(response)


def GetIssueState(issue_id):
  """Returns either 'closed' or 'open' for the given bug ID.

  Args:
    issue_id: string or string-castable object containing a numeric bug ID.
  Returns:
    'open' or 'closed' depending on the state of the bug.
  Raises:
    IssueTrackerQueryException if the data cannot be retrieved or parsed.
  """
  try:
    query_response = QuerySingleIssue(issue_id)
    # We assume the query returns a single result hence the [0]
    issue_detail = query_response['feed']['entry'][0]
    state = issue_detail['issues$state']['$t']
    return state
  except urllib2.URLError:
    raise IssueTrackerQueryException(
        'Could not fetch the details form the issue tracker.')
  except ValueError:
    raise IssueTrackerQueryException(
        'Could not parse the issue tracker\'s response as a json doc.')
  except KeyError:
    raise IssueTrackerQueryException(
        'The data from the issue tracker is not in the expected format.')


def CheckIssueClosed(issue_id):
  """Checks if a given issue is closed. Returns False when in doubt."""
  # We only check when issue_id appears to be valid
  if str(issue_id).isdigit():
    try:
      return GetIssueState(issue_id) == 'closed'
    except IssueTrackerQueryException:
      # We let this fall through to the return False
      pass
  # We return False for anything other than a positive number
  return False
