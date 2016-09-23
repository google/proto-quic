# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""This module contains functionality for starting build try jobs via HTTP.

This includes both sending a request to start a job, and also related code
for querying the status of the job.

This module can be either run as a stand-alone script to send a request to a
builder, or imported and used by calling the public functions below.
"""

import json
import urllib2

# URL template for fetching JSON data about builds.
BUILDER_JSON_URL = ('%(server_url)s/json/builders/%(bot_name)s/builds/'
                    '%(build_num)s?as_text=1&filter=0')

# URL template for displaying build steps.
BUILDER_HTML_URL = '%(server_url)s/builders/%(bot_name)s/builds/%(build_num)s'

# Status codes that can be returned by the GetBuildStatus method
# From buildbot.status.builder.
# See: http://docs.buildbot.net/current/developer/results.html
SUCCESS, WARNINGS, FAILURE, SKIPPED, EXCEPTION, RETRY, TRYPENDING = range(7)
OK = (SUCCESS, WARNINGS)  # These indicate build is complete.
FAILED = (FAILURE, EXCEPTION, SKIPPED)  # These indicate build failure.
PENDING = (RETRY, TRYPENDING)  # These indicate in progress or in pending queue.


class ServerAccessError(Exception):

  def __str__(self):
    return '%s\nSorry, cannot connect to server.' % self.args[0]


def _IsBuildRunning(build_data):
  """Checks whether the build is in progress on buildbot.

  Presence of currentStep element in build JSON indicates build is in progress.

  Args:
    build_data: A dictionary with build data, loaded from buildbot JSON API.

  Returns:
    True if build is in progress, otherwise False.
  """
  current_step = build_data.get('currentStep')
  if (current_step and current_step.get('isStarted') and
      current_step.get('results') is None):
    return True
  return False


def _IsBuildFailed(build_data):
  """Checks whether the build failed on buildbot.

  Sometime build status is marked as failed even though compile and packaging
  steps are successful. This may happen due to some intermediate steps of less
  importance such as gclient revert, generate_telemetry_profile are failed.
  Therefore we do an addition check to confirm if build was successful by
  calling _IsBuildSuccessful.

  Args:
    build_data: A dictionary with build data, loaded from buildbot JSON API.

  Returns:
    True if revision is failed build, otherwise False.
  """
  if (build_data.get('results') in FAILED and
      not _IsBuildSuccessful(build_data)):
    return True
  return False


def _IsBuildSuccessful(build_data):
  """Checks whether the build succeeded on buildbot.

  We treat build as successful if the package_build step is completed without
  any error i.e., when results attribute of the this step has value 0 or 1
  in its first element.

  Args:
    build_data: A dictionary with build data, loaded from buildbot JSON API.

  Returns:
    True if revision is successfully build, otherwise False.
  """
  if build_data.get('steps'):
    for item in build_data.get('steps'):
      # The 'results' attribute of each step consists of two elements,
      # results[0]: This represents the status of build step.
      # See: http://docs.buildbot.net/current/developer/results.html
      # results[1]: List of items, contains text if step fails, otherwise empty.
      if (item.get('name') == 'package_build' and
          item.get('isFinished') and
          item.get('results')[0] in OK):
        return True
  return False


def _FetchBuilderData(builder_url):
  """Fetches JSON data for the all the builds from the try server.

  Args:
    builder_url: A try server URL to fetch builds information.

  Returns:
    A dictionary with information of all build on the try server.
  """
  data = None
  try:
    url = urllib2.urlopen(builder_url)
  except urllib2.URLError as e:
    print ('urllib2.urlopen error %s, waterfall status page down.[%s]' % (
        builder_url, str(e)))
    return None
  if url is not None:
    try:
      data = url.read()
    except IOError as e:
      print 'urllib2 file object read error %s, [%s].' % (builder_url, str(e))
  return data


def _GetBuildData(buildbot_url):
  """Gets build information for the given build id from the try server.

  Args:
    buildbot_url: A try server URL to fetch build information.

  Returns:
    A dictionary with build information if build exists, otherwise None.
  """
  builds_json = _FetchBuilderData(buildbot_url)
  if builds_json:
    return json.loads(builds_json)
  return None


def GetBuildStatus(build_num, bot_name, server_url):
  """Gets build status from the buildbot status page for a given build number.

  Args:
    build_num: A build number on try server to determine its status.
    bot_name: Name of the bot where the build information is scanned.
    server_url: URL of the buildbot.

  Returns:
    A pair which consists of build status (SUCCESS, FAILED or PENDING) and a
    link to build status page on the waterfall.
  """
  results_url = None
  if build_num:
    # Get the URL for requesting JSON data with status information.
    buildbot_url = BUILDER_JSON_URL % {
        'server_url': server_url,
        'bot_name': bot_name,
        'build_num': build_num,
    }
    build_data = _GetBuildData(buildbot_url)
    if build_data:
      # Link to build on the buildbot showing status of build steps.
      results_url = BUILDER_HTML_URL % {
          'server_url': server_url,
          'bot_name': bot_name,
          'build_num': build_num,
      }
      if _IsBuildFailed(build_data):
        return (FAILED, results_url)

      elif _IsBuildSuccessful(build_data):
        return (OK, results_url)
  return (PENDING, results_url)


def GetBuildNumFromBuilder(build_reason, bot_name, server_url):
  """Gets build number on build status page for a given 'build reason'.

  This function parses the JSON data from buildbot page and collects basic
  information about the all the builds, and then uniquely identifies the build
  based on the 'reason' attribute in the JSON data about the build.

  The 'reason' attribute set is when a build request is posted, and it is used
  to identify the build on status page.

  Args:
    build_reason: A unique build name set to build on try server.
    bot_name: Name of the bot where the build information is scanned.
    server_url: URL of the buildbot.

  Returns:
    A build number as a string if found, otherwise None.
  """
  buildbot_url = BUILDER_JSON_URL % {
      'server_url': server_url,
      'bot_name': bot_name,
      'build_num': '_all',
  }
  builds_json = _FetchBuilderData(buildbot_url)
  if builds_json:
    builds_data = json.loads(builds_json)
    for current_build in builds_data:
      if builds_data[current_build].get('reason') == build_reason:
        return builds_data[current_build].get('number')
  return None
