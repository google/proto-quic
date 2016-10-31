#!/usr/bin/python
# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Convert SVN based DEPS into .DEPS.git for use with NewGit."""

import collections
from cStringIO import StringIO
import json
import optparse
import os
import Queue
import shutil
import subprocess
import sys
import threading
import time

import deps_utils
import git_tools
import svn_to_git_public

try:
  import git_cache
except ImportError:
  for p in os.environ['PATH'].split(os.pathsep):
    if (os.path.basename(p) == 'depot_tools' and
        os.path.exists(os.path.join(p, 'git_cache.py'))):
      sys.path.append(p)
  import git_cache

Job = collections.namedtuple(
    'Job',
    ['dep', 'git_url', 'dep_url', 'path', 'git_host', 'dep_rev', 'svn_branch'])

ConversionResults = collections.namedtuple(
    'ConversionResults',
    ['new_deps', 'deps_vars', 'bad_git_urls', 'bad_dep_urls', 'bad_git_hash'])

# This is copied from depot_tools/gclient.py
DEPS_OS_CHOICES = {
    "win32": "win",
    "win": "win",
    "cygwin": "win",
    "darwin": "mac",
    "mac": "mac",
    "unix": "unix",
    "linux": "unix",
    "linux2": "unix",
    "linux3": "unix",
    "android": "android",
}


def SplitScmUrl(url):
  """Given a repository, return a set containing the URL and the revision."""
  url_split = url.split('@')
  scm_url = url_split[0]
  scm_rev = 'HEAD'
  if len(url_split) == 2:
    scm_rev = url_split[1]
  return (scm_url, scm_rev)


def SvnRevToGitHash(
    svn_rev, git_url, repos_path, workspace, dep_path, git_host,
    svn_branch_name=None, cache_dir=None, outbuf=None, shallow=None):
  """Convert a SVN revision to a Git commit id."""
  git_repo = None
  if git_url.startswith(git_host):
    git_repo = git_url.replace(git_host, '')
  else:
    raise RuntimeError('Unknown git server %s, host %s' % (git_url, git_host))
  if repos_path is None and workspace is None and cache_dir is None:
    # We're running without a repository directory (i.e. no -r option).
    # We cannot actually find the commit id, but this mode is useful
    # just for testing the URL mappings.  Produce an output file that
    # can't actually be used, but can be eyeballed for correct URLs.
    return 'xxx-r%s' % svn_rev
  if repos_path:
    mirror = True
    git_repo_path = os.path.join(repos_path, git_repo)
    if not os.path.exists(git_repo_path) or not os.listdir(git_repo_path):
      git_tools.Clone(git_url, git_repo_path, mirror, outbuf)
  elif cache_dir:
    mirror = True
    git_repo_path = git_tools.PopulateCache(git_url, shallow)
  else:
    mirror = False
    git_repo_path = os.path.join(workspace, dep_path)
    if (os.path.exists(git_repo_path) and
        not os.path.exists(os.path.join(git_repo_path, '.git'))):
      # shutil.rmtree is unreliable on windows
      if sys.platform == 'win32':
        for _ in xrange(3):
          if not subprocess.call(['cmd.exe', '/c', 'rd', '/q', '/s',
                                  os.path.normcase(git_repo_path)]):
            break
          time.sleep(3)
      else:
        shutil.rmtree(git_repo_path)
    if not os.path.exists(git_repo_path):
      git_tools.Clone(git_url, git_repo_path, mirror, outbuf)

  if svn_branch_name:
    # svn branches are mirrored with:
    # branches = branches/*:refs/remotes/branch-heads/*
    if mirror:
      refspec = 'refs/branch-heads/' + svn_branch_name
    else:
      refspec = 'refs/remotes/branch-heads/' + svn_branch_name
  else:
    if mirror:
      refspec = 'refs/heads/master'
    else:
      refspec = 'refs/remotes/origin/master'

  # Work-around for:
  #   http://code.google.com/p/chromium/issues/detail?id=362222
  if (git_url.startswith('https://chromium.googlesource.com/external/pefile')
      and int(svn_rev) in (63, 141)):
    return '72c6ae42396cb913bcab63c15585dc3b5c3f92f1'

  return git_tools.Search(git_repo_path, svn_rev, mirror, refspec, git_url)


def MessageMain(message_q, threads):
  while True:
    try:
      msg = message_q.get(True, 10)
    except Queue.Empty:
      print >> sys.stderr, 'Still working on:'
      for s in sorted([th.working_on for th in threads if th.working_on]):
        print >> sys.stderr, '  %s' % s
      continue
    if msg is Queue.Empty:
      return
    if msg:
      print >> sys.stderr, msg


def ConvertDepMain(dep_q, message_q, options, results):
  cur_thread = threading.current_thread()
  while True:
    try:
      job = dep_q.get(False)
      dep, git_url, dep_url, path, git_host, dep_rev, svn_branch = job
      cur_thread.working_on = dep
    except Queue.Empty:
      cur_thread.working_on = None
      return

    outbuf = StringIO()
    def _print(s):
      for l in s.splitlines():
        outbuf.write('[%s] %s\n' % (dep, l))

    if options.verify:
      delay = 0.5
      success = False
      for try_index in range(1, 6):
        _print('checking %s (try #%d) ...' % (git_url, try_index))
        if git_tools.Ping(git_url, verbose=True):
          _print(' success')
          success = True
          break
        _print(' failure')
        _print('sleeping for %.01f seconds ...' % delay)
        time.sleep(delay)
        delay *= 2

      if not success:
        results.bad_git_urls.add(git_url)

    # Get the Git hash based off the SVN rev.
    git_hash = ''
    if dep_rev != 'HEAD':
      # Pass-through the hash for Git repositories. Resolve the hash for
      # subversion repositories.
      if dep_url.endswith('.git'):
        git_hash = '@%s' % dep_rev
      else:
        try:
          git_hash = '@%s' % SvnRevToGitHash(
              dep_rev, git_url, options.repos, options.workspace, path,
              git_host, svn_branch, options.cache_dir)
        except Exception as e:
          if options.no_fail_fast:
            results.bad_git_hash.append(e)
            continue
          raise

    # If this is webkit, we need to add the var for the hash.
    if dep == 'src/third_party/WebKit' and dep_rev:
      results.deps_vars['webkit_rev'] = git_hash
      git_hash = 'VAR_WEBKIT_REV'

    # Hack to preserve the angle_revision variable in .DEPS.git.
    # This will go away as soon as deps2git does.
    if dep == 'src/third_party/angle' and git_hash:
      # Cut the leading '@' so this variable has the same semantics in
      # DEPS and .DEPS.git.
      results.deps_vars['angle_revision'] = git_hash[1:]
      git_hash = 'VAR_ANGLE_REVISION'

    # Add this Git dep to the new deps.
    results.new_deps[path] = '%s%s' % (git_url, git_hash)

    message_q.put(outbuf.getvalue())


def ConvertDepsToGit(deps, options, deps_vars, svn_to_git_objs):
  """Convert a 'deps' section in a DEPS file from SVN to Git."""
  results = ConversionResults(
      new_deps={},
      deps_vars=deps_vars,
      bad_git_urls=set([]),
      bad_dep_urls=[],
      bad_git_hash=[]
  )

  # Populate our deps list.
  deps_to_process = Queue.Queue()
  for dep, dep_url in deps.iteritems():
    if not dep_url:  # dep is 'None' and emitted to exclude the dep
      results.new_deps[dep] = None
      continue

    # Get the URL and the revision/hash for this dependency.
    dep_url, dep_rev = SplitScmUrl(deps[dep])

    path = dep
    git_url = dep_url
    svn_branch = None
    git_host = dep_url

    if not dep_url.endswith('.git'):
      # Convert this SVN URL to a Git URL.
      for svn_git_converter in svn_to_git_objs:
        converted_data = svn_git_converter.SvnUrlToGitUrl(dep, dep_url)
        if converted_data:
          path, git_url, git_host = converted_data[:3]
          if len(converted_data) > 3:
            svn_branch = converted_data[3]
          break
      else:
        # Make all match failures fatal to catch errors early. When a match is
        # found, we break out of the loop so the exception is not thrown.
        if options.no_fail_fast:
          results.bad_dep_urls.append(dep_url)
          continue
        raise RuntimeError('No match found for %s' % dep_url)

    deps_to_process.put(
        Job(dep, git_url, dep_url, path, git_host, dep_rev, svn_branch))

  threads = []
  message_q = Queue.Queue()
  thread_args = (deps_to_process, message_q, options, results)
  num_threads = options.num_threads or deps_to_process.qsize()
  for _ in xrange(num_threads):
    th = threading.Thread(target=ConvertDepMain, args=thread_args)
    th.working_on = None
    th.start()
    threads.append(th)
  message_th = threading.Thread(target=MessageMain, args=(message_q, threads))
  message_th.start()

  for th in threads:
    th.join()
  message_q.put(Queue.Empty)
  message_th.join()

  return results


def main():
  parser = optparse.OptionParser()
  parser.add_option('-d', '--deps', default='DEPS',
                    help='path to the DEPS file to convert')
  parser.add_option('-o', '--out',
                    help='path to the converted DEPS file (default: stdout)')
  parser.add_option('-j', '--num-threads', type='int', default=4,
                    help='Maximum number of threads')
  parser.add_option('-t', '--type',
                    help='[DEPRECATED] type of DEPS file (public, etc)')
  parser.add_option('-x', '--extra-rules',
                    help='Path to file with additional conversion rules.')
  parser.add_option('-r', '--repos',
                    help='path to the directory holding all the Git repos')
  parser.add_option('-w', '--workspace', metavar='PATH',
                    help='top level of a git-based gclient checkout')
  parser.add_option('-c', '--cache_dir',
                    help='top level of a gclient git cache diretory.')
  parser.add_option('-s', '--shallow', action='store_true',
                    help='Use shallow checkouts when populating cache dirs.')
  parser.add_option('--no_fail_fast', action='store_true',
                    help='Try to process the whole DEPS, rather than failing '
                    'on the first bad entry.')
  parser.add_option('--verify', action='store_true',
                    help='ping each Git repo to make sure it exists')
  parser.add_option('--json',
                    help='path to a JSON file for machine-readable output')
  options = parser.parse_args()[0]

  # Get the content of the DEPS file.
  deps, deps_os, include_rules, skip_child_includes, hooks = (
      deps_utils.GetDepsContent(options.deps))

  if options.extra_rules and options.type:
    parser.error('Can\'t specify type and extra-rules at the same time.')
  elif options.type:
    options.extra_rules = os.path.join(
        os.path.abspath(os.path.dirname(__file__)),
        'svn_to_git_%s.py' % options.type)
  if options.cache_dir and options.repos:
    parser.error('Can\'t specify both cache_dir and repos at the same time.')
  if options.shallow and not options.cache_dir:
    parser.error('--shallow only supported with --cache_dir.')

  if options.cache_dir:
    options.cache_dir = os.path.abspath(options.cache_dir)

  if options.extra_rules and not os.path.exists(options.extra_rules):
    raise RuntimeError('Can\'t locate rules file "%s".' % options.extra_rules)

  # Create a var containing the Git and Webkit URL, this will make it easy for
  # people to use a mirror instead.
  git_url = 'https://chromium.googlesource.com'
  deps_vars = {
      'git_url': git_url,
      'webkit_url': git_url + '/chromium/blink.git',
  }

  # Find and load svn_to_git_* modules that handle the URL mapping.
  svn_to_git_objs = [svn_to_git_public]
  if options.extra_rules:
    rules_dir, rules_file = os.path.split(options.extra_rules)
    rules_file_base = os.path.splitext(rules_file)[0]
    sys.path.insert(0, rules_dir)
    svn_to_git_mod = __import__(rules_file_base)
    svn_to_git_objs.insert(0, svn_to_git_mod)

  # If a workspace parameter is given, and a .gclient file is present, limit
  # DEPS conversion to only the repositories that are actually used in this
  # checkout.  Also, if a cache dir is specified in .gclient, honor it.
  if options.workspace and os.path.exists(
      os.path.join(options.workspace, '.gclient')):
    gclient_file = os.path.join(options.workspace, '.gclient')
    gclient_dict = {}
    try:
      execfile(gclient_file, {}, gclient_dict)
    except IOError:
      print >> sys.stderr, 'Could not open %s' % gclient_file
      raise
    except SyntaxError:
      print >> sys.stderr, 'Could not parse %s' % gclient_file
      raise
    target_os = gclient_dict.get('target_os', [])
    if not target_os or not gclient_dict.get('target_os_only'):
      target_os.append(DEPS_OS_CHOICES.get(sys.platform, 'unix'))
    if 'all' not in target_os:
      deps_os = dict([(k, v) for k, v in deps_os.iteritems() if k in target_os])
    if not options.cache_dir and 'cache_dir' in gclient_dict:
      options.cache_dir = os.path.abspath(gclient_dict['cache_dir'])

  if options.cache_dir:
    git_cache.Mirror.SetCachePath(options.cache_dir)
  else:
    try:
      options.cache_dir = git_cache.Mirror.GetCachePath()
    except RuntimeError:
      pass

  # Do general pre-processing of the DEPS data.
  for svn_git_converter in svn_to_git_objs:
    if hasattr(svn_git_converter, 'CleanDeps'):
      svn_git_converter.CleanDeps(deps, deps_os, include_rules,
                                  skip_child_includes, hooks)

  # Convert the DEPS file to Git.
  results = ConvertDepsToGit(
      deps, options, deps_vars, svn_to_git_objs)
  for os_dep in deps_os:
    os_results = ConvertDepsToGit(deps_os[os_dep], options, deps_vars,
                                  svn_to_git_objs)
    deps_os[os_dep] = os_results.new_deps
    results.bad_git_urls.update(os_results.bad_git_urls)
    results.bad_dep_urls.extend(os_results.bad_dep_urls)
    results.bad_git_hash.extend(os_results.bad_git_hash)

  if options.json:
    with open(options.json, 'w') as f:
      json.dump(list(results.bad_git_urls), f, sort_keys=True, indent=2)

  if results.bad_git_urls:
    print >> sys.stderr, ('\nUnable to resolve the following repositories. '
        'Please make sure\nthat any svn URLs have a git mirror associated with '
        'them.\nTo see the exact error, run `git ls-remote [repository]` where'
        '\n[repository] is the URL ending in .git (strip off the @revision\n'
        'number.) For more information, visit http://code.google.com\n'
        '/p/chromium/wiki/UsingGit#Adding_new_repositories_to_DEPS.\n')
    for dep in results.bad_git_urls:
      print >> sys.stderr, ' ' + dep
  if results.bad_dep_urls:
    print >> sys.stderr, '\nNo mappings found for the following urls:\n'
    for bad in results.bad_dep_urls:
      print >> sys.stderr, ' ' + bad
  if results.bad_git_hash:
    print >> sys.stderr, '\nsvn rev to git hash failures:\n'
    for bad in results.bad_git_hash:
      print >> sys.stderr, ' ' + str(bad)

  if (results.bad_git_urls or results.bad_dep_urls or results.bad_git_hash):
    return 2

  if options.verify:
    print >> sys.stderr, ('\nAll referenced repositories were successfully '
                          'resolved.')
    return 0

  # Write the DEPS file to disk.
  deps_utils.WriteDeps(options.out, deps_vars, results.new_deps, deps_os,
                       include_rules, skip_child_includes, hooks)
  return 0


if '__main__' == __name__:
  sys.exit(main())
