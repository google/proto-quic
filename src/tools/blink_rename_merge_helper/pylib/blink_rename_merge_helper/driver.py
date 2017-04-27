# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

_BEFORE_RENAME_COMMIT = '5e27d4b8d16d9830e52a44a44b4ff501a2a2e667'
_RENAME_COMMIT = '1c4d759e44259650dfb2c426a7f997d2d0bc73dc'
_AFTER_RENAME_COMMIT = 'b0bf8e8ed34ba40acece03baa19446a5d91b009d'
_DEVNULL = open(os.devnull, 'w')
_SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
_GIT_CONFIG_BRANCH_RECORDS = 'branch.%s.blink-rename-resolver-records'
_GIT_ATTRIBUTES_PATH = os.path.join('.git', 'info', 'attributes')


class _MergeTool(object):
  """Scoper object for using the Blink Rename merge driver helper."""

  def __init__(self):
    self.__attributes_backup = None

  def __enter__(self):
    _check_call_git(
        ['config', 'merge.blink-rename.name', 'blink rename merge helper'])
    # Note: while it would be possible to encode the path to the records
    # directory here, it's easier to pass it as an environmental variable, to
    # avoid weird escaping issues.
    _check_call_git([
        'config', 'merge.blink-rename.driver',
        '%s %%O %%A %%B %%P' % os.path.join(_SCRIPT_DIR, 'merge.py')
    ])
    _check_call_git(['config', 'merge.blink-rename.recursive', 'binary'])

    if os.path.exists(_GIT_ATTRIBUTES_PATH):
      filemode = 'r+'
    else:
      filemode = 'w'
    with open(_GIT_ATTRIBUTES_PATH, filemode) as attributes_file:
      if filemode == 'r+':
        self.__attributes_backup = attributes_file.read()
        attributes_file.seek(0)
        attributes_file.truncate()
      attributes_file.write('# Blink Rename merge helper\n')
      attributes_file.write('*.cc merge=blink-rename\n')
      attributes_file.write('*.cpp merge=blink-rename\n')
      attributes_file.write('*.mm merge=blink-rename\n')
      attributes_file.write('*.h merge=blink-rename\n')

  def __exit__(self, exc_type, exc_value, traceback):
    _check_call_git(['config', '--remove-section', 'merge.blink-rename'])
    if self.__attributes_backup:
      try:
        with open(_GIT_ATTRIBUTES_PATH, 'w') as attributes_file:
          attributes_file.write(self.__attributes_backup)
      except IOError:
        print 'ERROR: Failed to restore original %s file' % _GIT_ATTRIBUTES_PATH
        print '       Original contents:'
        print self.__attributes_backup
    else:
      os.remove(_GIT_ATTRIBUTES_PATH)


def _call_gclient(args):
  if sys.platform == 'win32':
    args = ['gclient.bat'] + args
  else:
    args = ['gclient'] + args
  return subprocess.call(args)


def _build_ninja_command(args):
  if sys.platform == 'win32':
    return ['ninja.exe'] + args
  else:
    return ['ninja'] + args


def _call_ninja_silently(args):
  # Eat output, since only the return value is important.
  return subprocess.call(
      _build_ninja_command(args), stdout=_DEVNULL, stderr=_DEVNULL)


def _call_ninja(args):
  return subprocess.call(_build_ninja_command(args))


def _build_git_command(args):
  if sys.platform == 'win32':
    return ['git.bat'] + args
  else:
    return ['git'] + args


def _call_git(args, **kwargs):
  return subprocess.call(_build_git_command(args), **kwargs)


def _check_call_git(args, **kwargs):
  return subprocess.check_call(_build_git_command(args), **kwargs)


def _check_call_git_and_get_output(args, **kwargs):
  return subprocess.check_output(_build_git_command(args), **kwargs)


def _check_call_python(args):
  if sys.platform == 'win32':
    args = ['python.exe'] + args
  else:
    args = ['python'] + args
  return subprocess.check_call(args)


def _is_clean_tree():
  return _call_git(['diff-index', '--quiet', 'HEAD']) == 0


def _ensure_clean_tree():
  if not _is_clean_tree():
    print 'ERROR: cannot proceed with a dirty tree. Please commit or stash '
    print '       changes.'
    sys.exit(1)


def _get_branch_info():
  current_branch = _check_call_git_and_get_output(
      ['rev-parse', '--symbolic-full-name', 'HEAD']).strip()
  print 'INFO: current branch: %s' % current_branch

  tracking_branch = None
  try:
    tracking_branch = _check_call_git_and_get_output(
        ['rev-parse', '--symbolic-full-name', 'HEAD@{upstream}']).strip()
  except subprocess.CalledProcessError:
    # Likely failed because there's no tracking branch info. Fall through and
    # fail out.
    pass
  if not tracking_branch:
    print 'ERROR: no tracking branch found. Bailing out...'
    print '       If you want to track origin/master, then run:'
    print '           git branch --set-upstream-to origin/master'
    sys.exit(1)

  print 'INFO: tracking branch: %s' % tracking_branch
  return current_branch, tracking_branch


def _commit_is_ancestor_of(ancestor, commit):
  # merge-base --is-ancestor returns 0 if |ancestor| is the ancestor of
  # |commit|.
  return _call_git(['merge-base', '--is-ancestor', ancestor, commit]) == 0


def _ensure_origin_contains_commit():
  if not _commit_is_ancestor_of(_RENAME_COMMIT, 'refs/remotes/origin/master'):
    _check_call_git(['fetch', 'origin'])


def _prompt_yes_or_no(question, default='yes'):
  choices = {
      'yes': True,
      'y': True,
      'no': False,
      'n': False,
  }
  assert default in choices

  if default == 'yes':
    prompt = '[Y/n]'
  elif default == 'no':
    prompt = '[y/N]'
  else:
    prompt = '[y/n]'

  while True:
    choice = raw_input('%s %s? ' % (question, prompt)).lower()
    if default and not choice:
      return choices[default]
    elif choice in choices:
      return choices[choice]
    else:
      print 'Please answer Yes or No.'


def _dump_edits_for_debugging(edits):
  fd, debug_path = tempfile.mkstemp()
  print 'INFO: dumping raw edits to %s' % debug_path
  os.write(fd, edits)
  os.close(fd)


def _prompt_for_squash(commits_in_branch):
  print('WARNING: there are %d commits in branch that are not upstream.' %
        commits_in_branch)
  print '         Squashing into one commit is required to continue.'
  if _prompt_yes_or_no('Automatically squash into one commit'):
    auto_squasher = os.path.join(_SCRIPT_DIR, 'auto_squasher.py')
    return _call_git(
        ['rebase', '-i', 'HEAD~%d' % commits_in_branch],
        env=dict(os.environ,
                 GIT_SEQUENCE_EDITOR='python %s' % auto_squasher)) == 0
  else:
    sys.exit(1)


def _prepare_branch(current_branch,
                    tracking_branch,
                    build_dir,
                    jobs,
                    rebase=True):
  if not build_dir:
    print 'ERROR: the build directory must be specified with -C when running '
    print '       --prepare mode.'
    sys.exit(1)
  if not _commit_is_ancestor_of(_BEFORE_RENAME_COMMIT, tracking_branch):
    print 'ERROR: tracking branch not prepared yet; run --prepare on tracking '
    print '       branch first.'
    sys.exit(1)
  if (tracking_branch != 'refs/remotes/origin/master' and
      _commit_is_ancestor_of(_RENAME_COMMIT, tracking_branch)):
    print 'ERROR: tracking branch already contains rename commit; bailing out '
    print '       since the tool cannot handle this automatically.'
    sys.exit(1)
  if _commit_is_ancestor_of(_RENAME_COMMIT, 'HEAD'):
    print 'ERROR: current branch appears to already be updated.'
    sys.exit(1)

  commits_in_branch = int(
      _check_call_git_and_get_output([
          'rev-list', '--left-only', '--count', 'HEAD...%s' % tracking_branch
      ]))
  if rebase and commits_in_branch != 1:
    if _prompt_for_squash(commits_in_branch):
      commits_in_branch = 1

  update_args = []
  if rebase:
    update_args.append('rebase')
  else:
    update_args.append('merge')
  if tracking_branch == 'refs/remotes/origin/master':
    update_args.append(_BEFORE_RENAME_COMMIT)
  if _call_git(update_args) != 0:
    print 'ERROR: failed to update branch to the commit before the rename.'
    print '       Fix any conflicts and try running with --prepare again.'
    sys.exit(1)

  if _call_gclient(['sync']):
    print 'ERROR: gclient sync returned a non-zero exit code.'
    print '       Please fix the errors and try running with --prepare again.'
    sys.exit(1)

  changed_files = _check_call_git_and_get_output(
      ['diff', '--name-only',
       'HEAD~%d' % commits_in_branch]).strip().split('\n')
  # Filter changed files out to only the ones that still exist and that ninja
  # knows about.
  clang_scripts_dir = os.path.join('tools', 'clang', 'scripts')
  _check_call_python(
      [os.path.join(clang_scripts_dir, 'generate_compdb.py'), build_dir])
  with open(os.path.join(build_dir, 'compile_commands.json')) as f:
    compile_db = json.loads(f.read())
    files_in_db = set([
        os.path.realpath(os.path.join(build_dir, entry['file']))
        for entry in compile_db
    ])
    changed_buildable_files = [
        f for f in changed_files if os.path.realpath(f) in files_in_db
    ]

  if not changed_buildable_files:
    print 'INFO: This branch does not appear to change files that this script '
    print '      can help automatically rebase. Exiting...'
    sys.exit(0)

  # 'touch' changed files to force a rebuild.
  for f in changed_buildable_files:
    os.utime(f, None)

  # -d keeprsp is only needed for Windows, but it doesn't hurt to have it
  # elsewhere.
  ninja_args = ['-C', build_dir, '-d', 'keeprsp']
  if jobs:
    ninja_args.extend(['-j', jobs])
  # Source files are specified relative to the root of the build directory.
  targets = [
      '%s^' % os.path.relpath(f, build_dir) for f in changed_buildable_files
  ]
  ninja_args.extend(targets)
  if _call_ninja(ninja_args):
    print 'ERROR: Cannot continue, ninja failed!'
    sys.exit(1)

  staging_dir = os.path.abspath(
      os.path.join(os.getcwd(), 'tools', 'blink_rename_merge_helper',
                   'staging'))
  blocklist_path = os.path.join(staging_dir, 'data', 'idl_blocklist.txt')
  clang_tool_args = [
      'python', os.path.join(clang_scripts_dir, 'run_tool.py'),
      '--tool-args=--method-blocklist=%s' % blocklist_path,
      'rewrite_to_chrome_style', build_dir
  ]
  clang_tool_args.extend(changed_buildable_files)
  clang_tool_output = subprocess.check_output(
      clang_tool_args,
      env=dict(
          os.environ,
          PATH='%s%s%s' % (os.path.join(staging_dir, 'bin'), os.pathsep,
                           os.environ['PATH'])))

  # Extract the edits from the clang tool's output.
  p = subprocess.Popen(
      ['python', os.path.join(clang_scripts_dir, 'extract_edits.py')],
      stdin=subprocess.PIPE,
      stdout=subprocess.PIPE)
  edits, dummy_stderr = p.communicate(input=clang_tool_output)
  if p.returncode != 0:
    print 'ERROR: extracting edits from clang tool output failed.'
    sys.exit(1)

  _dump_edits_for_debugging(edits)

  # And apply them. Note this this intentionally uses changed_files instead of
  # changed_buildable_files, as changes to header files, etc should also be
  # recorded.
  p = subprocess.Popen(
      ['python', os.path.join(clang_scripts_dir, 'apply_edits.py'), build_dir] +
      changed_files,
      stdin=subprocess.PIPE)
  p.communicate(input=edits)
  if p.returncode != 0:
    print 'WARNING: failed to apply %d edits from clang tool.' % -p.returncode
    if not _prompt_yes_or_no('Continue (generally safe)', default='yes'):
      sys.exit(1)

  # Use git apply with --include
  apply_manual_patch_args = [
      'apply', '--reject', os.path.join(staging_dir, 'data', 'manual.patch')
  ]
  for f in changed_files:
    apply_manual_patch_args.append('--include=%s' % f)
  if _call_git(apply_manual_patch_args) != 0:
    print 'ERROR: failed to apply manual patches. Please manually resolve '
    print '       conflicts (without committing) and re-run the tool with '
    print '       --finish-prepare.'
    sys.exit(1)

  _finish_prepare_branch(current_branch)


def _finish_prepare_branch(current_branch):
  _check_call_git(['cl', 'format'])

  # Record changed files in a temporary data store for later use in conflict
  # resolution.
  files_to_save = _check_call_git_and_get_output(
      ['diff', '--name-only']).strip().split()
  if not files_to_save:
    print 'INFO: no changed files. Exiting...'
    sys.exit(0)

  record_dir = tempfile.mkdtemp()
  print 'INFO: saving changed files to %s' % record_dir

  for file_to_save in files_to_save:
    # Skip files that are deleted, since resolving those conflicts should be
    # trivial.
    # TODO(dcheng): Be more clever and stage this fact somehow?
    if not os.path.isfile(file_to_save):
      continue
    print 'Saving %s' % file_to_save
    shutil.copyfile(file_to_save,
                    os.path.join(record_dir,
                                 hashlib.sha256(file_to_save).hexdigest()))

  _check_call_git(
      ['config', _GIT_CONFIG_BRANCH_RECORDS % current_branch, record_dir])
  _check_call_git(['reset', '--hard'])
  print 'INFO: finished preparing branch %s' % current_branch


def _update_branch(current_branch, tracking_branch, rebase=True):
  if not _commit_is_ancestor_of(_BEFORE_RENAME_COMMIT, tracking_branch):
    print 'ERROR: tracking branch not prepared yet; run --prepare on tracking '
    print '       branch first.'
    sys.exit(1)
  if not _commit_is_ancestor_of(_RENAME_COMMIT, tracking_branch):
    print 'ERROR: tracking branch not updated yet; run --update on tracking '
    print '       branch first.'
    sys.exit(1)
  if tracking_branch != 'refs/remotes/origin/master' and _commit_is_ancestor_of(
      _AFTER_RENAME_COMMIT, tracking_branch):
    print 'WARNING: tracking branch is already ahead of the rename commit.'
    print '         The reliability of the tool will be much lower.'
    if not _prompt_yes_or_no('Continue', default='no'):
      sys.exit(1)
  if not _commit_is_ancestor_of(_BEFORE_RENAME_COMMIT, 'HEAD'):
    print 'ERROR: current branch not yet prepared; run --prepare first.'
    sys.exit(1)
  if _commit_is_ancestor_of(_RENAME_COMMIT, 'HEAD'):
    print 'ERROR: current branch appears to already be updated.'
    sys.exit(1)
  prepared_records = None
  try:
    prepared_records = _check_call_git_and_get_output(
        ['config', '--get',
         _GIT_CONFIG_BRANCH_RECORDS % current_branch]).strip()
  except subprocess.CalledProcessError:
    # Likely failed because it's not set. Fall through and fail out
    pass
  if not prepared_records:
    print 'ERROR: current branch is not prepared yet; run --prepare first.'
    sys.exit(1)

  if not os.path.isdir(prepared_records):
    print 'ERROR: records directory %s is invalid.' % prepared_records
    sys.exit(1)

  # TODO(dcheng): Ideally this part would be automated, but I'm failing to think
  # of a nice way to do it...
  args = []
  if rebase:
    args.append('rebase')
  else:
    args.append('merge')
  if tracking_branch == 'refs/remotes/origin/master':
    args.append(_RENAME_COMMIT)
  with _MergeTool():
    if _call_git(
        args, env=dict(os.environ,
                       BLINK_RENAME_RECORDS_PATH=prepared_records)) != 0:
      print 'ERROR: failed to update. Please resolve any remaining conflicts '
      print '       manually.'

  print 'INFO: updated branch %s' % current_branch


def run():
  # run.py made a poor life choice. Workaround that here by (hopefully) changing
  # the working directory back to the git repo root.
  os.chdir(os.path.join('..', '..'))

  parser = argparse.ArgumentParser()
  parser.add_argument('-C', metavar='DIR', help='Path to build directory.')
  parser.add_argument(
      '-j', metavar='N', help='Number of ninja jobs to run in parallel.')
  parser.add_argument(
      '--merge',
      action='store_true',
      help='Use merge instead of rebase to update the branch. Not recommended.')
  tool_mode = parser.add_mutually_exclusive_group(required=True)
  tool_mode.add_argument(
      '--prepare',
      action='store_true',
      help='Prepare the branch for updating across the rename commit.')
  tool_mode.add_argument(
      '--finish-prepare',
      action='store_true',
      help='Finish preparing the branch for updating across the rename commit.')
  tool_mode.add_argument(
      '--update',
      action='store_true',
      help='Update the branch across the rename commit.')
  args = parser.parse_args()

  current_branch, tracking_branch = _get_branch_info()

  if tracking_branch != 'refs/remotes/origin/master':
    print 'WARNING: The script is more fragile when the tracking branch '
    print '         is not refs/remotes/origin/master.'
    # Default to danger mode.
    if not _prompt_yes_or_no('Continue', default='yes'):
      sys.exit(1)

  _ensure_origin_contains_commit()

  if args.prepare:
    _ensure_clean_tree()
    _prepare_branch(current_branch, tracking_branch, args.C, args.j,
                    not args.merge)
  elif args.finish_prepare:
    _finish_prepare_branch(current_branch)
  else:
    _ensure_clean_tree()
    _update_branch(current_branch, tracking_branch, not args.merge)
