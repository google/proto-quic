#!/usr/bin/python
# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Read .DEPS.git and use the information to update git submodules"""

import optparse
import os
import re
import subprocess
import sys

from deps_utils import GetDepsContent


SHA1_RE = re.compile('[0-9a-fA-F]{40}')


def SanitizeDeps(submods):
  """
  Look for conflicts (primarily nested submodules) in submodule data.  In the
  case of a conflict, the higher-level (shallower) submodule takes precedence.
  Modifies the submods argument in-place.
  """
  for submod_name in submods.keys():
    parts = submod_name.split('/')[:-1]
    while parts:
      may_conflict = '/'.join(parts)
      if may_conflict in submods:
        msg = ('Warning: dropping submodule "%s", because '
               'it is nested in submodule "%s".' % (submod_name, may_conflict))
        print >> sys.stderr, msg
        submods.pop(submod_name)
        break
      parts.pop()
  return submods


def CollateDeps(deps_content):
  """
  Take the output of deps_utils.GetDepsContent and return a hash of:

  { submod_name : [ [ submod_os, ... ], submod_url, submod_sha1 ], ... }
  """
  fixdep = lambda x: x[4:] if x.startswith('src/') else x
  spliturl = lambda x: list(x.partition('@')[0::2]) if x else [None, None]
  submods = {}
  # Non-OS-specific DEPS always override OS-specific deps. This is an interim
  # hack until there is a better way to handle OS-specific DEPS.
  for (deps_os, val) in deps_content[1].iteritems():
    for (dep, url) in val.iteritems():
      submod_data = submods.setdefault(fixdep(dep), [[]] + spliturl(url))
      submod_data[0].append(deps_os)
  for (dep, url) in deps_content[0].iteritems():
    submods[fixdep(dep)] = [['all']] + spliturl(url)
  return submods


def WriteGitmodules(submods, gitless=False, rewrite_rules=None):
  """
  Take the output of CollateDeps, use it to write a .gitmodules file and
  return a map of submodule name -> sha1 to be added to the git index.
  """
  adds = {}
  if not rewrite_rules:
    rewrite_rules = []
  def _rewrite(url):
    if not url:
      return url
    for rule in rewrite_rules:
      if url.startswith(rule[0]):
        return rule[1] + url[len(rule[0]):]
    return url
  fh = open('.gitmodules', 'w')
  for submod in sorted(submods.keys()):
    [submod_os, submod_url, submod_sha1] = submods[submod]
    submod_url = _rewrite(submod_url)
    print >> fh, '[submodule "%s"]' % submod
    print >> fh, '\tpath = %s' % submod
    print >> fh, '\turl = %s' % (submod_url if submod_url else '')
    print >> fh, '\tos = %s' % ','.join(submod_os)
    if submod_sha1 and not SHA1_RE.match(submod_sha1):
      raise RuntimeError('sha1 hash "%s" for submodule "%s" is malformed' %
                         (submod_sha1, submod))
    if gitless or not submod_url:
      continue
    if not submod_sha1:
      # We don't know what sha1 to register, so we have to infer it from the
      # submodule's origin/master.
      if not os.path.exists(os.path.join(submod, '.git')):
        # Not cloned yet
        subprocess.check_call(['git', 'clone', '-n', submod_url, submod])
      else:
        # Already cloned; let's fetch
        subprocess.check_call(['git', 'fetch', 'origin'], cwd=submod)
      sub = subprocess.Popen(['git', 'rev-list', 'origin/HEAD^!'],
                             cwd=submod, stdout=subprocess.PIPE)
      submod_sha1 = sub.communicate()[0].rstrip()
    adds[submod] = submod_sha1
  fh.close()
  if not gitless:
    subprocess.check_call(['git', 'add', '.gitmodules'])
  return adds


def RemoveObsoleteSubmodules():
  """
  Delete from the git repository any submodules which aren't in .gitmodules.
  """
  lsfiles_proc = subprocess.Popen(['git', 'ls-files', '-s'],
                                  stdout=subprocess.PIPE)
  grep_proc = subprocess.Popen(['grep', '^160000'],
                               stdin = lsfiles_proc.stdout,
                               stdout=subprocess.PIPE)
  (grep_out, _) = grep_proc.communicate() or ('', '')
  lsfiles_proc.communicate()
  with open(os.devnull, 'w') as nullpipe:
    for line in grep_out.splitlines():
      [_, _, _, path] = line.split()
      cmd = ['git', 'config', '-f', '.gitmodules',
             '--get-regexp', 'submodule\..*\.path', '^%s$' % path]
      try:
        subprocess.check_call(cmd, stdout=nullpipe)
      except subprocess.CalledProcessError:
        subprocess.check_call(['git', 'update-index', '--force-remove', path])


def main():
  parser = optparse.OptionParser()
  parser.add_option('--gitless', action='store_true',
                    help='Skip all actions that assume a git working copy '
                         '(to support presubmit checks)')
  parser.add_option('--rewrite-url', action='append', metavar='OLD_URL=NEW_URL',
                    default=[], help='Translate urls according to this rule')
  options, args = parser.parse_args()
  if args:
    deps_file = args[0]
  else:
    deps_file = '.DEPS.git'

  rewrite_rules = []
  for rule in options.rewrite_url:
    (old_url, new_url) = rule.split('=', 1)
    if not old_url or not new_url:
      print 'Bad url rewrite rule: "%s"' % rule
      parser.print_help()
      return 1
    rewrite_rules.append((old_url, new_url))
      

  # 9/18/2012 -- HACK to fix try bots without restarting
  hack_deps_file = os.path.join('src', '.DEPS.git')
  if not os.path.exists(deps_file) and os.path.exists(hack_deps_file):
    deps_file = hack_deps_file
        
  adds = WriteGitmodules(SanitizeDeps(CollateDeps(GetDepsContent(deps_file))),
                  rewrite_rules=rewrite_rules, gitless=options.gitless)
  if not options.gitless:
    RemoveObsoleteSubmodules()
    for submod_path, submod_sha1 in adds.iteritems():
      subprocess.check_call(['git', 'update-index', '--add',
                             '--cacheinfo', '160000', submod_sha1, submod_path])
  return 0


if __name__ == '__main__':
  sys.exit(main())
