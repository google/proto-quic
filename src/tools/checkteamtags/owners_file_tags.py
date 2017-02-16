# Copyright (c) 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import re

from collections import defaultdict


def parse(filename):
  """Searches the file for lines that start with `# TEAM:` or `# COMPONENT:`.

  Args:
    filename (str): path to the file to parse.
  Returns:
    (team (str), component(str)): The team and component found in the file, the
        last one of each if multiple, None if missing.
  """
  team = None
  component = None
  team_regex = re.compile('\s*#\s*TEAM\s*:\s*(\S+)')
  component_regex = re.compile('\s*#\s*COMPONENT\s*:\s*(\S+)')
  with open(filename) as f:
    for line in f:
      team_matches = team_regex.match(line)
      if team_matches:
        team = team_matches.group(1)
      component_matches = component_regex.match(line)
      if component_matches:
        component = component_matches.group(1)
  return team, component


def aggregate_components_from_owners(root):
  """Traverses the given dir and parse OWNERS files for team and component tags.

  Args:
    root (str): the path to the src directory.

  Returns:
    A tuple (data, warnings, errors, stats) where data is a dict of the form
      {'component-to-team': {'Component1': 'team1@chr...', ...},
       'dir-to-component': {'/path/to/1': 'Component1', ...}}
      , warnings is a list of strings, stats is a dict of form
      {'OWNERS-count': total number of OWNERS files,
       'OWNERS-with-component-only-count': number of OWNERS have # COMPONENT,
       'OWNERS-with-team-and-component-count': number of
                          OWNERS have TEAM and COMPONENT,
       'OWNERS-count-by-depth': {directory depth: number of OWNERS},
       'OWNERS-with-component-only-count-by-depth': {directory depth: number
                          of OWNERS have COMPONENT at this depth},
       'OWNERS-with-team-and-component-count-by-depth':{directory depth: ...}}
  """
  stats = {}
  num_total = 0
  num_with_component = 0
  num_with_team_component = 0
  num_total_by_depth = defaultdict(int)
  num_with_component_by_depth = defaultdict(int)
  num_with_team_component_by_depth = defaultdict(int)
  warnings = []
  component_to_team = defaultdict(set)
  dir_to_component = {}
  for dirname, _, files in os.walk(root):
    # Proofing against windows casing oddities.
    owners_file_names = [f for f in files if f.upper() == 'OWNERS']
    if owners_file_names:
      file_depth = dirname[len(root) + len(os.path.sep):].count(os.path.sep)
      num_total += 1
      num_total_by_depth[file_depth] += 1
      owners_full_path = os.path.join(dirname, owners_file_names[0])
      owners_rel_path = os.path.relpath(owners_full_path, root)
      team, component = parse(owners_full_path)
      if component:
        num_with_component += 1
        num_with_component_by_depth[file_depth] += 1
        dir_to_component[os.path.relpath(dirname, root)] = component
        if team:
          num_with_team_component += 1
          num_with_team_component_by_depth[file_depth] += 1
          component_to_team[component].add(team)
      else:
        warnings.append('%s has no COMPONENT tag' % owners_rel_path)
  mappings = {'component-to-team': component_to_team,
              'dir-to-component': dir_to_component}
  errors = validate_one_team_per_component(mappings)
  stats = {'OWNERS-count': num_total,
           'OWNERS-with-component-only-count': num_with_component,
           'OWNERS-with-team-and-component-count': num_with_team_component,
           'OWNERS-count-by-depth': num_total_by_depth,
           'OWNERS-with-component-only-count-by-depth':
           num_with_component_by_depth,
           'OWNERS-with-team-and-component-count-by-depth':
           num_with_team_component_by_depth}
  return unwrap(mappings), warnings, errors, stats


def validate_one_team_per_component(m):
  """Validates that each component is associated with at most 1 team."""
  errors = []
  # TODO(robertocn): Validate the component names: crbug.com/679540
  component_to_team = m['component-to-team']
  for c in component_to_team:
    if len(component_to_team[c]) > 1:
      errors.append('Component %s has more than one team assigned to it: %s' % (
          c, ', '.join(list(component_to_team[c]))))
  return errors


def unwrap(mappings):
  """Remove the set() wrapper around values in component-to-team mapping."""
  for c in mappings['component-to-team']:
    mappings['component-to-team'][c] = mappings['component-to-team'][c].pop()
  return mappings
