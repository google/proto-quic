#!/usr/bin/env python
# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import argparse
import collections
import logging
import os
import re
import subprocess
import sys
import time

extra_trybots = [
  {
    "mastername": "master.tryserver.chromium.win",
    "buildernames": ["win_optional_gpu_tests_rel"]
  },
  {
    "mastername": "master.tryserver.chromium.mac",
    "buildernames": ["mac_optional_gpu_tests_rel"]
  },
  {
    "mastername": "master.tryserver.chromium.linux",
    "buildernames": ["linux_optional_gpu_tests_rel"]
  },
  {
    "mastername": "master.tryserver.chromium.android",
    "buildernames": ["android_optional_gpu_tests_rel"]
  },
]

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
SRC_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, os.pardir))
sys.path.insert(0, os.path.join(SRC_DIR, 'build'))
import find_depot_tools
find_depot_tools.add_depot_tools_to_path()
import roll_dep_svn
from gclient import GClientKeywords
from third_party import upload

# Avoid depot_tools/third_party/upload.py print verbose messages.
upload.verbosity = 0  # Errors only.

CHROMIUM_GIT_URL = 'https://chromium.googlesource.com/chromium/src.git'
CL_ISSUE_RE = re.compile('^Issue number: ([0-9]+) \((.*)\)$')
RIETVELD_URL_RE = re.compile('^https?://(.*)/(.*)')
ROLL_BRANCH_NAME = 'special_webgl_roll_branch'
TRYJOB_STATUS_SLEEP_SECONDS = 30

# Use a shell for subcommands on Windows to get a PATH search.
IS_WIN = sys.platform.startswith('win')
WEBGL_PATH = os.path.join('third_party', 'webgl', 'src')
WEBGL_REVISION_TEXT_FILE = os.path.join(
  'content', 'test', 'gpu', 'gpu_tests', 'webgl_conformance_revision.txt')

CommitInfo = collections.namedtuple('CommitInfo', ['git_commit',
                                                   'git_repo_url'])
CLInfo = collections.namedtuple('CLInfo', ['issue', 'url', 'rietveld_server'])

def _PosixPath(path):
  """Convert a possibly-Windows path to a posix-style path."""
  (_, path) = os.path.splitdrive(path)
  return path.replace(os.sep, '/')

def _ParseGitCommitHash(description):
  for line in description.splitlines():
    if line.startswith('commit '):
      return line.split()[1]
  logging.error('Failed to parse git commit id from:\n%s\n', description)
  sys.exit(-1)
  return None


def _ParseDepsFile(filename):
  with open(filename, 'rb') as f:
    deps_content = f.read()
  return _ParseDepsDict(deps_content)


def _ParseDepsDict(deps_content):
  local_scope = {}
  var = GClientKeywords.VarImpl({}, local_scope)
  global_scope = {
    'From': GClientKeywords.FromImpl,
    'Var': var.Lookup,
    'deps_os': {},
  }
  exec(deps_content, global_scope, local_scope)
  return local_scope


def _GenerateCLDescriptionCommand(webgl_current, webgl_new, bugs):
  def GetChangeString(current_hash, new_hash):
    return '%s..%s' % (current_hash[0:7], new_hash[0:7]);

  def GetChangeLogURL(git_repo_url, change_string):
    return '%s/+log/%s' % (git_repo_url, change_string)

  def GetBugString(bugs):
    bug_str = 'BUG='
    for bug in bugs:
      bug_str += str(bug) + ','
    return bug_str.rstrip(',')

  change_str = GetChangeString(webgl_current.git_commit,
                               webgl_new.git_commit)
  changelog_url = GetChangeLogURL(webgl_current.git_repo_url,
                                  change_str)
  if webgl_current.git_commit == webgl_new.git_commit:
    print 'WARNING: WebGL repository is unchanged; proceeding with no-op roll'

  def GetExtraTrybotString():
    s = ''
    for t in extra_trybots:
      if s:
        s += ';'
      s += t['mastername'] + ':' + ','.join(t['buildernames'])
    return s

  extra_trybot_args = []
  if extra_trybots:
    extra_trybot_string = GetExtraTrybotString()
    extra_trybot_args = ['-m', 'CQ_INCLUDE_TRYBOTS=' + extra_trybot_string]

  return [
    '-m', 'Roll WebGL ' + change_str,
    '-m', '%s' % changelog_url,
    '-m', GetBugString(bugs),
    '-m', 'TEST=bots',
  ] + extra_trybot_args


class AutoRoller(object):
  def __init__(self, chromium_src):
    self._chromium_src = chromium_src

  def _RunCommand(self, command, working_dir=None, ignore_exit_code=False,
                  extra_env=None):
    """Runs a command and returns the stdout from that command.

    If the command fails (exit code != 0), the function will exit the process.
    """
    working_dir = working_dir or self._chromium_src
    logging.debug('cmd: %s cwd: %s', ' '.join(command), working_dir)
    env = os.environ.copy()
    if extra_env:
      logging.debug('extra env: %s', extra_env)
      env.update(extra_env)
    p = subprocess.Popen(command, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, shell=IS_WIN, env=env,
                         cwd=working_dir, universal_newlines=True)
    output = p.stdout.read()
    p.wait()
    p.stdout.close()
    p.stderr.close()

    if not ignore_exit_code and p.returncode != 0:
      logging.error('Command failed: %s\n%s', str(command), output)
      sys.exit(p.returncode)
    return output

  def _GetCommitInfo(self, path_below_src, git_hash=None, git_repo_url=None):
    working_dir = os.path.join(self._chromium_src, path_below_src)
    self._RunCommand(['git', 'fetch', 'origin'], working_dir=working_dir)
    revision_range = git_hash or 'origin'
    ret = self._RunCommand(
        ['git', '--no-pager', 'log', revision_range,
         '--no-abbrev-commit', '--pretty=full', '-1'],
        working_dir=working_dir)
    return CommitInfo(_ParseGitCommitHash(ret), git_repo_url)

  def _GetDepsCommitInfo(self, deps_dict, path_below_src):
    entry = deps_dict['deps'][_PosixPath('src/%s' % path_below_src)]
    at_index = entry.find('@')
    git_repo_url = entry[:at_index]
    git_hash = entry[at_index + 1:]
    return self._GetCommitInfo(path_below_src, git_hash, git_repo_url)

  def _GetCLInfo(self):
    cl_output = self._RunCommand(['git', 'cl', 'issue'])
    m = CL_ISSUE_RE.match(cl_output.strip())
    if not m:
      logging.error('Cannot find any CL info. Output was:\n%s', cl_output)
      sys.exit(-1)
    issue_number = int(m.group(1))
    url = m.group(2)

    # Parse the Rietveld host from the URL.
    m = RIETVELD_URL_RE.match(url)
    if not m:
      logging.error('Cannot parse Rietveld host from URL: %s', url)
      sys.exit(-1)
    rietveld_server = m.group(1)
    return CLInfo(issue_number, url, rietveld_server)

  def _GetCurrentBranchName(self):
    return self._RunCommand(
        ['git', 'rev-parse', '--abbrev-ref', 'HEAD']).splitlines()[0]

  def _IsTreeClean(self):
    lines = self._RunCommand(
      ['git', 'status', '--porcelain', '-uno']).splitlines()
    if len(lines) == 0:
      return True

    logging.debug('Dirty/unversioned files:\n%s', '\n'.join(lines))
    return False

  def _GetBugList(self, path_below_src, webgl_current, webgl_new):
    # TODO(kbr): this isn't useful, at least not yet, when run against
    # the WebGL Github repository.
    working_dir = os.path.join(self._chromium_src, path_below_src)
    lines = self._RunCommand(
        ['git','log',
            '%s..%s' % (webgl_current.git_commit, webgl_new.git_commit)],
        working_dir=working_dir).split('\n')
    bugs = set()
    for line in lines:
      line = line.strip()
      bug_prefix = 'BUG='
      if line.startswith(bug_prefix):
        bugs_strings = line[len(bug_prefix):].split(',')
        for bug_string in bugs_strings:
          try:
            bugs.add(int(bug_string))
          except:
            # skip this, it may be a project specific bug such as
            # "angleproject:X" or an ill-formed BUG= message
            pass
    return bugs

  def _UpdateReadmeFile(self, readme_path, new_revision):
    readme = open(os.path.join(self._chromium_src, readme_path), 'r+')
    txt = readme.read()
    m = re.sub(re.compile('.*^Revision\: ([0-9]*).*', re.MULTILINE),
        ('Revision: %s' % new_revision), txt)
    readme.seek(0)
    readme.write(m)
    readme.truncate()

  def PrepareRoll(self, ignore_checks, run_tryjobs):
    # TODO(kjellander): use os.path.normcase, os.path.join etc for all paths for
    # cross platform compatibility.

    if not ignore_checks:
      if self._GetCurrentBranchName() != 'master':
        logging.error('Please checkout the master branch.')
        return -1
      if not self._IsTreeClean():
        logging.error('Please make sure you don\'t have any modified files.')
        return -1

    # Always clean up any previous roll.
    self.Abort()

    logging.debug('Pulling latest changes')
    if not ignore_checks:
      self._RunCommand(['git', 'pull'])

    self._RunCommand(['git', 'checkout', '-b', ROLL_BRANCH_NAME])

    # Modify Chromium's DEPS file.

    # Parse current hashes.
    deps_filename = os.path.join(self._chromium_src, 'DEPS')
    deps = _ParseDepsFile(deps_filename)
    webgl_current = self._GetDepsCommitInfo(deps, WEBGL_PATH)

    # Find ToT revisions.
    webgl_latest = self._GetCommitInfo(WEBGL_PATH)

    if IS_WIN:
      # Make sure the roll script doesn't use windows line endings
      self._RunCommand(['git', 'config', 'core.autocrlf', 'true'])

    self._UpdateDep(deps_filename, WEBGL_PATH, webgl_latest)
    self._UpdateWebGLRevTextFile(WEBGL_REVISION_TEXT_FILE, webgl_latest)

    if self._IsTreeClean():
      logging.debug('Tree is clean - no changes detected.')
      self._DeleteRollBranch()
    else:
      bugs = self._GetBugList(WEBGL_PATH, webgl_current, webgl_latest)
      description = _GenerateCLDescriptionCommand(
          webgl_current, webgl_latest, bugs)
      logging.debug('Committing changes locally.')
      self._RunCommand(['git', 'add', '--update', '.'])
      self._RunCommand(['git', 'commit'] + description)
      logging.debug('Uploading changes...')
      self._RunCommand(['git', 'cl', 'upload'],
                       extra_env={'EDITOR': 'true'})

      if run_tryjobs:
        # Kick off tryjobs.
        base_try_cmd = ['git', 'cl', 'try']
        self._RunCommand(base_try_cmd)
        if extra_trybots:
          # Run additional tryjobs.
          # TODO(kbr): this should not be necessary -- the
          # CQ_INCLUDE_TRYBOTS directive above should handle it.
          # http://crbug.com/585237
          for trybot in extra_trybots:
            for builder in trybot['buildernames']:
              self._RunCommand(base_try_cmd + [
                  '-m', trybot['mastername'],
                  '-b', builder])

      cl_info = self._GetCLInfo()
      print 'Issue: %d URL: %s' % (cl_info.issue, cl_info.url)

    # Checkout master again.
    self._RunCommand(['git', 'checkout', 'master'])
    print 'Roll branch left as ' + ROLL_BRANCH_NAME
    return 0

  def _UpdateDep(self, deps_filename, dep_relative_to_src, commit_info):
    dep_name = _PosixPath(os.path.join('src', dep_relative_to_src))

    # roll_dep_svn.py relies on cwd being the Chromium checkout, so let's
    # temporarily change the working directory and then change back.
    cwd = os.getcwd()
    os.chdir(os.path.dirname(deps_filename))
    roll_dep_svn.update_deps(deps_filename, dep_relative_to_src, dep_name,
                             commit_info.git_commit, '')
    os.chdir(cwd)

  def _UpdateWebGLRevTextFile(self, txt_filename, commit_info):
    # Rolling the WebGL conformance tests must cause at least all of
    # the WebGL tests to run. There are already exclusions in
    # trybot_analyze_config.json which force all tests to run if
    # changes under src/content/test/gpu are made. (This rule
    # typically only takes effect on the GPU bots.) To make sure this
    # happens all the time, update an autogenerated text file in this
    # directory.
    with open(txt_filename, 'w') as fh:
      print >> fh, '# AUTOGENERATED FILE - DO NOT EDIT'
      print >> fh, '# SEE roll_webgl_conformance.py'
      print >> fh, 'Current webgl revision %s' % commit_info.git_commit

  def _DeleteRollBranch(self):
    self._RunCommand(['git', 'checkout', 'master'])
    self._RunCommand(['git', 'branch', '-D', ROLL_BRANCH_NAME])
    logging.debug('Deleted the local roll branch (%s)', ROLL_BRANCH_NAME)


  def _GetBranches(self):
    """Returns a tuple of active,branches.

    The 'active' is the name of the currently active branch and 'branches' is a
    list of all branches.
    """
    lines = self._RunCommand(['git', 'branch']).split('\n')
    branches = []
    active = ''
    for l in lines:
      if '*' in l:
        # The assumption is that the first char will always be the '*'.
        active = l[1:].strip()
        branches.append(active)
      else:
        b = l.strip()
        if b:
          branches.append(b)
    return (active, branches)

  def Abort(self):
    active_branch, branches = self._GetBranches()
    if active_branch == ROLL_BRANCH_NAME:
      active_branch = 'master'
    if ROLL_BRANCH_NAME in branches:
      print 'Aborting pending roll.'
      self._RunCommand(['git', 'checkout', ROLL_BRANCH_NAME])
      # Ignore an error here in case an issue wasn't created for some reason.
      self._RunCommand(['git', 'cl', 'set_close'], ignore_exit_code=True)
      self._RunCommand(['git', 'checkout', active_branch])
      self._RunCommand(['git', 'branch', '-D', ROLL_BRANCH_NAME])
    return 0


def main():
  parser = argparse.ArgumentParser(
      description='Auto-generates a CL containing a WebGL conformance roll.')
  parser.add_argument('--abort',
    help=('Aborts a previously prepared roll. '
          'Closes any associated issues and deletes the roll branches'),
    action='store_true')
  parser.add_argument('--ignore-checks', action='store_true', default=False,
      help=('Skips checks for being on the master branch, dirty workspaces and '
            'the updating of the checkout. Will still delete and create local '
            'Git branches.'))
  parser.add_argument('--run-tryjobs', action='store_true', default=False,
      help=('Start the dry-run tryjobs for the newly generated CL. Use this '
            'when you have no need to make changes to the WebGL conformance '
            'test expectations in the same CL and want to avoid.'))
  parser.add_argument('-v', '--verbose', action='store_true', default=False,
      help='Be extra verbose in printing of log messages.')
  args = parser.parse_args()

  if args.verbose:
    logging.basicConfig(level=logging.DEBUG)
  else:
    logging.basicConfig(level=logging.ERROR)

  autoroller = AutoRoller(SRC_DIR)
  if args.abort:
    return autoroller.Abort()
  else:
    return autoroller.PrepareRoll(args.ignore_checks, args.run_tryjobs)

if __name__ == '__main__':
  sys.exit(main())
