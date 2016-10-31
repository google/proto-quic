#!/usr/bin/python
# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import cStringIO
import os
import re
import subprocess
import sys
import threading

try:
  import git_cache
except ImportError:
  for p in os.environ['PATH'].split(os.pathsep):
    if (os.path.basename(p) == 'depot_tools' and
        os.path.exists(os.path.join(p, 'git_cache.py'))):
      sys.path.append(p)
  import git_cache


# Show more information about the commands being executed.
VERBOSE = False

# The longest any single subprocess will be allowed to run.
TIMEOUT = 40 * 60

class AbnormalExit(Exception):
  pass


class StdioBuffer(object):
  def __init__(self, name, out_queue):
    self.closed = False
    self.line_buffer = cStringIO.StringIO()
    self.name = name
    self.out_q = out_queue

  def write(self, msg):
    """Write into the buffer.  Only one thread should call write() at a time."""
    assert not self.closed
    self.line_buffer.write(msg)
    # We can use '\n' instead of os.linesep because universal newlines is
    # set to true below.
    if '\n' in msg:
      # We can assert that lines is at least 2 items if '\n' is present.
      lines = self.line_buffer.getvalue().split('\n')
      for line in lines[:-1]:
        self.out_q.put('%s> %s' % (self.name, line))
      self.line_buffer.close()
      self.line_buffer = cStringIO.StringIO()
      self.line_buffer.write(lines[-1])

  def close(self):
    # Empty out the line buffer.
    self.write('\n')
    self.out_q.put(None)
    self.closed = True


def GetStatusOutput(cmd, cwd=None, out_buffer=None):
  """Return (status, output) of executing cmd in a shell."""
  if VERBOSE:
    print >> sys.stderr, ''
    print >> sys.stderr, '[DEBUG] Running "%s"' % cmd

  def _thread_main():
    thr = threading.current_thread()
    thr.status = -1
    thr.stdout = ''
    thr.stderr = '<timeout>'
    try:
      if out_buffer:
        proc = subprocess.Popen(cmd, shell=True,
                                cwd=cwd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        while True:
          buf = proc.stdout.read(1)
          if buf == '\r':  # We want carriage returns in Linux to be newlines.
            buf = '\n'
          if not buf:
            break
          out_buffer.write(buf)
        stdout = ''
        proc.wait()
        out_buffer.close()
      else:
        proc = subprocess.Popen(cmd, shell=True, universal_newlines=True,
                                cwd=cwd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        (stdout, _) = proc.communicate()
    except Exception, e:
      thr.status = -1
      thr.stdout = ''
      thr.stderr = repr(e)
    else:
      thr.status = proc.returncode
      thr.stdout = stdout
      thr.stderr = ''

  thr = threading.Thread(target=_thread_main)
  thr.daemon = True
  thr.start()
  thr.join(TIMEOUT)

  # pylint: disable=E1101
  if VERBOSE:
    short_output = ' '.join(thr.stdout.splitlines())
    short_output = short_output.strip(' \t\n\r')
    print >> sys.stderr, (
        '[DEBUG] Output: %d, %-60s' % (thr.status, short_output))

  return (thr.status, thr.stdout)


def Git(git_repo, command, is_mirror=False, out_buffer=None):
  """Execute a git command within a local git repo."""
  if is_mirror:
    if git_repo:
      cmd = 'git --git-dir=%s %s' % (git_repo, command)
    else:
      cmd = 'git %s' % command
    cwd = None
  else:
    cmd = 'git %s' % command
    cwd = git_repo
  (status, output) = GetStatusOutput(cmd, cwd, out_buffer)
  # For Abnormal Exit, Windows returns -1, Posix returns 128.
  if status in [-1, 128]:
    raise AbnormalExit('Failed to run %s. Exited Abnormally. output %s' %
                       (cmd, output))
  elif status != 0:
    raise Exception('Failed to run %s. error %d. output %s' % (cmd, status,
                                                               output))
  return (status, output)


def Clone(git_url, git_repo, is_mirror, out_buffer=None):
  """Clone a repository."""
  cmd = 'clone'
  if is_mirror:
    cmd += ' --mirror'
  cmd += ' %s %s'  % (git_url, git_repo)

  if not is_mirror and not os.path.exists(git_repo):
    os.makedirs(git_repo)

  return Git(None, cmd, is_mirror=is_mirror, out_buffer=out_buffer)


def PopulateCache(git_url, shallow=False):
  # --shallow by default checks out 10000 revision, but for really large
  # repos like adobe ones, we want significantly less than 10000.
  depth = None
  if shallow and 'adobe' in git_url:
    depth = 10
  mirror = git_cache.Mirror(git_url, print_func=lambda *args: None)
  mirror.populate(depth=depth, shallow=shallow)
  return mirror.mirror_path


def Fetch(git_repo, git_url, is_mirror):
  """Fetch the latest objects for a given git repository."""
  # Always update the upstream url
  Git(git_repo, 'config remote.origin.url %s' % git_url)
  Git(git_repo, 'fetch origin', is_mirror)


def Ping(git_repo, verbose=False):
  """Confirm that a remote repository URL is valid."""
  status, stdout = GetStatusOutput('git ls-remote ' + git_repo)
  if status != 0 and verbose:
    print >> sys.stderr, stdout
  return status == 0


def CreateLessThanOrEqualRegex(number):
  """ Return a regular expression to test whether an integer less than or equal
      to 'number' is present in a given string.
  """

  # In three parts, build a regular expression that match any numbers smaller
  # than 'number'.
  # For example, 78656 would give a regular expression that looks like:
  # Part 1
  # (78356|                        # 78356
  # Part 2
  #  7835[0-5]|                    # 78350-78355
  #  783[0-4][0-9]|                # 78300-78349
  #  78[0-2][0-9][0-9]|            # 78000-78299
  #  7[0-7][0-9][0-9][0-9]|        # 70000-77999
  #  [0-6][0-9][0-9][0-9][0-9]|    # 10000-69999
  # Part 3
  #  [0-9][0-9][0-9][0-9]|         # 1000-9999
  #  [0-9][0-9][0-9]|              # 100-999
  #  [0-9][0-9]|                   # 10-99
  #  [0-9])                        # 0-9

  # Part 1: Create an array with all the regexes, as described above.
  # Prepopulate it with the number itself.
  number = str(number)
  expressions = [number]

  # Convert the number to a list, so we can translate digits in it to
  # expressions.
  num_list = list(number)
  num_len = len(num_list)

  # Part 2: Go through all the digits in the number, starting from the end.
  # Each iteration appends a line to 'expressions'.
  for index in range (num_len - 1, -1, -1):
    # Convert this digit back to an integer.
    digit = int(num_list[index])

    # Part 2.1: No processing if this digit is a zero.
    if digit == 0:
      continue

    # Part 2.2: We switch the current digit X by a range "[0-(X-1)]".
    num_list[index] = '[0-%d]' % (digit - 1)

    # Part 2.3: We set all following digits to be "[0-9]".
    # Since we just decrementented a digit in a most important position, all
    # following digits don't matter. The possible numbers will always be smaller
    # than before we decremented.
    for next_digit in range(index + 1, num_len):
      num_list[next_digit] = '[0-9]'

    # Part 2.4: Add this new sub-expression to the list.
    expressions.append(''.join(num_list))

  # Part 3: We add all the full ranges to match all numbers that are at least
  # one order of magnitude smaller than the original numbers.
  for index in range(1, num_len):
    expressions.append('[0-9]'*index)

  # All done. We now have our final regular expression.
  regex = '(%s)' % ('|'.join(expressions))
  return regex


class SearchError(Exception):
  pass


def _SearchImpl(git_repo, svn_rev, is_mirror, refspec, fetch_url, regex):
  def _FindRevForCommitish(git_repo, commitish, is_mirror):
    _, output = Git(git_repo, 'cat-file commit %s' % commitish, is_mirror)
    match = re.match(r'git-svn-id: [^\s@]+@(\d+) \S+$', output.splitlines()[-1])
    if match:
      return int(match.group(1))
    else:
      # The last commit isn't from svn, but maybe the repo was converted to pure
      # git at some point, so the last svn commit is somewhere farther back.
      _, output = Git(
          git_repo, ('log -E --grep="^git-svn-id: [^@]*@[0-9]* [A-Za-z0-9-]*$" '
                     '-1 --format="%%H" %s') % commitish, is_mirror)
      assert output, 'no match on %s' % commitish

  # Check if svn_rev is newer than the current refspec revision.
  try:
    found_rev = _FindRevForCommitish(git_repo, refspec, is_mirror)
  # Sometimes this fails because it's looking in a branch that hasn't been
  # fetched from upstream yet. Let it fetch and try again.
  except AbnormalExit:
    found_rev = None
  if (not found_rev or found_rev < int(svn_rev)) and fetch_url:
    if VERBOSE:
      print >> sys.stderr, (
          'Fetching %s %s [%s < %s]' % (git_repo, refspec, found_rev, svn_rev))
    Fetch(git_repo, fetch_url, is_mirror)
    found_rev = _FindRevForCommitish(git_repo, refspec, is_mirror)

  # Find the first commit matching the given git-svn-id regex.
  _, output = Git(
      git_repo,
      ('log -E --grep="^git-svn-id: [^@]*@%s [A-Za-z0-9-]*$" '
       '-1 --format="%%H" %s') % (regex, refspec),
      is_mirror)
  output = output.strip()
  if not re.match('^[0-9a-fA-F]{40}$', output):
    raise SearchError('Cannot find revision %s in %s:%s' % (svn_rev, git_repo,
                                                            refspec))

  # Check if it actually matched the svn_rev that was requested.
  found_rev = _FindRevForCommitish(git_repo, output, is_mirror)
  found_msg = svn_rev
  if found_rev != int(svn_rev):
    found_msg = '%s [actual: %s]' % (svn_rev, found_rev)
  print >> sys.stderr, '%s: %s <-> %s' % (git_repo, output, found_msg)
  return output


def SearchExact(git_repo, svn_rev, is_mirror, refspec='FETCH_HEAD',
    fetch_url=None):
  """Return the Git commit id exactly matching the given SVN revision.

  If fetch_url is not None, will update repo if revision is newer."""
  regex = str(svn_rev)
  return _SearchImpl(git_repo, svn_rev, is_mirror, refspec, fetch_url, regex)


def Search(git_repo, svn_rev, is_mirror, refspec='FETCH_HEAD', fetch_url=None):
  """Return the Git commit id fuzzy matching the given SVN revision.

  If fetch_url is not None, will update repo if revision is newer."""
  regex = CreateLessThanOrEqualRegex(svn_rev)
  return _SearchImpl(git_repo, svn_rev, is_mirror, refspec, fetch_url, regex)
