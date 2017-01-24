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
    A pair (data, warnings) where data is a dict of the form
      {'component-to-team': {'Component1': 'team1@chr...', ...},
       'dir-to-component': {'/path/to/1': 'Component1', ...}}
      and warnings is a list of strings.
  """
  warnings = []
  component_to_team = defaultdict(set)
  dir_to_component = {}
  for dirname, _, files in os.walk(root):
    # Proofing against windows casing oddities.
    owners_file_names = [f for f in files if f.upper() == 'OWNERS']
    if owners_file_names:
      owners_full_path = os.path.join(dirname, owners_file_names[0])
      owners_rel_path = os.path.relpath(owners_full_path, root)
      team, component = parse(owners_full_path)
      if component:
        dir_to_component[os.path.relpath(dirname, root)] = component
        if team:
          component_to_team[component].add(team)
      else:
        warnings.append('%s has no COMPONENT tag' % owners_rel_path)
  mappings = {'component-to-team': component_to_team,
              'dir-to-component': dir_to_component}
  errors = validate_one_team_per_component(mappings)
  return unwrap(mappings), warnings, errors


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
