#!/usr/bin/env python
# Copyright (c) 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Makes sure OWNERS files have consistent TEAM and COMPONENT tags."""


import json
import logging
import optparse
import os
import sys


def check_owners(root, owners_path):
  """Component and Team check in OWNERS files. crbug.com/667954"""
  if root:
    full_path = os.path.join(root, owners_path)
    rel_path = owners_path
  else:
    full_path = os.path.abspath(owners_path)
    rel_path = os.path.relpath(owners_path)

  def result_dict(error):
    return {
      'error': error,
      'full_path': full_path,
      'rel_path': rel_path,
    }

  with open(full_path) as f:
    owners_file_lines = f.readlines()

  component_entries = [l for l in owners_file_lines if l.split()[:2] ==
                       ['#', 'COMPONENT:']]
  team_entries = [l for l in owners_file_lines if l.split()[:2] ==
                  ['#', 'TEAM:']]
  if len(component_entries) > 1:
    return result_dict('Contains more than one component per directory')
  if len(team_entries) > 1:
    return result_dict('Contains more than one team per directory')

  if not component_entries and not team_entries:
    return

  if component_entries:
    component = component_entries[0].split(':')[1]
    if not component:
      return result_dict('Has COMPONENT line but no component name')
    # Check for either of the following formats:
    #   component1, component2, ...
    #   component1,component2,...
    #   component1 component2 ...
    component_count = max(
        len(component.strip().split()),
        len(component.strip().split(',')))
    if component_count > 1:
      return result_dict('Has more than one component name')
    # TODO(robertocn): Check against a static list of valid components,
    # perhaps obtained from monorail at the beginning of presubmit.

  if team_entries:
    team_entry_parts = team_entries[0].split('@')
    if len(team_entry_parts) != 2:
      return result_dict('Has TEAM line, but not exactly 1 team email')
  # TODO(robertocn): Raise a warning if only one of (COMPONENT, TEAM) is
  # present.


def main():
  usage = """Usage: python %prog [--root <dir>] <owners_file1> <owners_file2>...
  owners_fileX  specifies the path to the file to check, these are expected
                to be relative to the root directory if --root is used.

Examples:
  python %prog --root /home/<user>/chromium/src/ tools/OWNERS v8/OWNERS
  python %prog /home/<user>/chromium/src/tools/OWNERS
  python %prog ./OWNERS
  """

  parser = optparse.OptionParser(usage=usage)
  parser.add_option(
      '--root', help='Specifies the repository root.')
  parser.add_option(
      '-v', '--verbose', action='count', default=0, help='Print debug logging')
  parser.add_option(
      '--bare',
      action='store_true',
      default=False,
      help='Prints the bare filename triggering the checks')
  parser.add_option('--json', help='Path to JSON output file')
  options, args = parser.parse_args()

  levels = [logging.ERROR, logging.INFO, logging.DEBUG]
  logging.basicConfig(level=levels[min(len(levels) - 1, options.verbose)])

  errors = filter(None, [check_owners(options.root, f) for f in args])

  if options.json:
    with open(options.json, 'w') as f:
      json.dump(errors, f)

  if errors:
    if options.bare:
      print '\n'.join(e['full_path'] for e in errors)
    else:
      print '\nFAILED\n'
      print '\n'.join('%s: %s' % (e['full_path'], e['error']) for e in errors)
    return 1
  if not options.bare:
    print '\nSUCCESS\n'
  return 0


if '__main__' == __name__:
  sys.exit(main())
