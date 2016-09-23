# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""This module contains functions for performing source control operations."""

import bisect_utils


def IsInGitRepository():
  output, _ = bisect_utils.RunGit(['rev-parse', '--is-inside-work-tree'])
  return output.strip() == 'true'


def GetRevisionList(end_revision_hash, start_revision_hash, cwd=None):
  """Retrieves a list of git commit hashes in a range.

  Args:
    end_revision_hash: The SHA1 for the end of the range, inclusive.
    start_revision_hash: The SHA1 for the beginning of the range, inclusive.

  Returns:
    A list of the git commit hashes in the range, in reverse time order --
    that is, starting with |end_revision_hash|.
  """
  revision_range = '%s..%s' % (start_revision_hash, end_revision_hash)
  cmd = ['log', '--format=%H', '-10000', '--first-parent', revision_range]
  log_output = bisect_utils.CheckRunGit(cmd, cwd=cwd)

  revision_hash_list = log_output.split()
  revision_hash_list.append(start_revision_hash)

  return revision_hash_list


def SyncToRevision(revision, sync_client=None):
  """Syncs or checks out a revision based on sync_client argument.

  Args:
    revision: Git hash for the solutions with the format <repo>@rev.
        E.g., "src@2ae43f...", "src/third_party/webkit@asr1234" etc.
    sync_client: Syncs to revision when this is True otherwise checks out
        the revision.

  Returns:
    True if sync or checkout is successful, False otherwise.
  """
  if not sync_client:
    _, return_code = bisect_utils.RunGit(['checkout', revision])
  elif sync_client == 'gclient':
    return_code = bisect_utils.RunGClientAndSync([revision])
  else:
    raise NotImplementedError('Unsupported sync_client: "%s"' % sync_client)

  return not return_code


def GetCurrentRevision(cwd=None):
  """Gets current revision of the given repository."""
  return bisect_utils.CheckRunGit(['rev-parse', 'HEAD'], cwd=cwd).strip()


def ResolveToRevision(revision_to_check, depot, depot_deps_dict,
                      search, cwd=None):
  """Tries to resolve an SVN revision or commit position to a git SHA1.

  Args:
    revision_to_check: The user supplied revision string that may need to be
        resolved to a git commit hash. This may be an SVN revision, git commit
        position, or a git commit hash.
    depot: The depot (dependency repository) that |revision_to_check| is from.
    depot_deps_dict: A dictionary with information about different depots.
    search: How many revisions forward or backward to search. If the value is
        negative, the function will search backwards chronologically, otherwise
        it will search forward.

  Returns:
    A string containing a git SHA1 hash, otherwise None.
  """
  # Android-chrome is git only, so no need to resolve this to anything else.
  if depot == 'android-chrome':
    return revision_to_check

  # If the given revision can't be parsed as an integer, then it may already
  # be a git commit hash.
  if not bisect_utils.IsStringInt(revision_to_check):
    return revision_to_check

  depot_svn = 'svn://svn.chromium.org/chrome/trunk/src'

  if depot != 'chromium':
    depot_svn = depot_deps_dict[depot]['svn']
  svn_revision = int(revision_to_check)
  git_revision = None

  if search > 0:
    search_range = xrange(svn_revision, svn_revision + search, 1)
  else:
    search_range = xrange(svn_revision, svn_revision + search, -1)

  for i in search_range:
    # NOTE: Checking for the git-svn-id footer is for backwards compatibility.
    # When we can assume that all the revisions we care about are from after
    # git commit positions started getting added, we don't need to check this.
    svn_pattern = 'git-svn-id: %s@%d' % (depot_svn, i)
    commit_position_pattern = '^Cr-Commit-Position: .*@{#%d}' % i
    cmd = ['log', '--format=%H', '-1', '--grep', svn_pattern,
           '--grep', commit_position_pattern, 'origin/master']
    log_output = bisect_utils.CheckRunGit(cmd, cwd=cwd)
    log_output = log_output.strip()

    if log_output:
      git_revision = log_output
      break

  return git_revision


def IsInProperBranch():
  """Checks whether the current branch is "master"."""
  cmd = ['rev-parse', '--abbrev-ref', 'HEAD']
  log_output = bisect_utils.CheckRunGit(cmd)
  log_output = log_output.strip()
  return log_output == 'master'


def GetCommitPosition(git_revision, cwd=None):
  """Finds git commit position for the given git hash.

  This function executes "git footer --position-num <git hash>" command to get
  commit position the given revision.

  Args:
    git_revision: The git SHA1 to use.
    cwd: Working directory to run the command from.

  Returns:
    Git commit position as integer or None.
  """
  # Some of the repositories are pure git based, unlike other repositories
  # they doesn't have commit position. e.g., skia, angle.
  cmd = ['footers', '--position-num', git_revision]
  output, return_code = bisect_utils.RunGit(cmd, cwd)
  if not return_code:
    commit_position = output.strip()
    if bisect_utils.IsStringInt(commit_position):
      return int(commit_position)
  return None


def GetCommitTime(git_revision, cwd=None):
  """Returns commit time for the given revision in UNIX timestamp."""
  cmd = ['log', '--format=%ct', '-1', git_revision]
  output = bisect_utils.CheckRunGit(cmd, cwd=cwd)
  return int(output)


def QueryRevisionInfo(revision, cwd=None):
  """Gathers information on a particular revision, such as author's name,
  email, subject, and date.

  Args:
    revision: Revision you want to gather information on; a git commit hash.

  Returns:
    A dict in the following format:
    {
      'author': %s,
      'email': %s,
      'date': %s,
      'subject': %s,
      'body': %s,
    }
  """
  commit_info = {}

  formats = ['%aN', '%aE', '%s', '%cD', '%b']
  targets = ['author', 'email', 'subject', 'date', 'body']

  for i in xrange(len(formats)):
    cmd = ['log', '--format=%s' % formats[i], '-1', revision]
    output = bisect_utils.CheckRunGit(cmd, cwd=cwd)
    commit_info[targets[i]] = output.rstrip()

  return commit_info


def CheckoutFileAtRevision(file_name, revision, cwd=None):
  """Performs a checkout on a file at the given revision.

  Returns:
    True if successful.
  """
  command = ['checkout', revision, file_name]
  _, return_code = bisect_utils.RunGit(command, cwd=cwd)
  return not return_code


def RevertFileToHead(file_name):
  """Un-stages a file and resets the file's state to HEAD.

  Returns:
    True if successful.
  """
  # Reset doesn't seem to return 0 on success.
  bisect_utils.RunGit(['reset', 'HEAD', file_name])
  _, return_code = bisect_utils.RunGit(
      ['checkout', bisect_utils.FILE_DEPS_GIT])
  return not return_code


def QueryFileRevisionHistory(filename, revision_start, revision_end):
  """Returns a list of commits that modified this file.

  Args:
    filename: Name of file.
    revision_start: Start of revision range (inclusive).
    revision_end: End of revision range.

  Returns:
    Returns a list of commits that touched this file.
  """
  cmd = [
      'log',
      '--format=%H',
      '%s~1..%s' % (revision_start, revision_end),
      '--',
      filename,
  ]
  output = bisect_utils.CheckRunGit(cmd)
  lines = output.split('\n')
  return [o for o in lines if o]
