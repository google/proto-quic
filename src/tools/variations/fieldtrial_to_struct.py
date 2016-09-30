#!/usr/bin/env python
# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import json
import os.path
import sys
import optparse
_script_path = os.path.realpath(__file__)

sys.path.insert(0, os.path.normpath(_script_path + "/../../json_comment_eater"))
try:
  import json_comment_eater
finally:
  sys.path.pop(0)

sys.path.insert(0, os.path.normpath(_script_path + "/../../json_to_struct"))
try:
  import json_to_struct
finally:
  sys.path.pop(0)

def _Load(filename):
  """Loads a JSON file into a Python object and return this object.
  """
  with open(filename, 'r') as handle:
    result = json.loads(json_comment_eater.Nom(handle.read()))
  return result

def _LoadFieldTrialConfig(filename):
  """Loads a field trial config JSON and converts it into a format that can be
  used by json_to_struct.
  """
  return _FieldTrialConfigToDescription(_Load(filename))

def _CreateGroup(group_data):
  group = {'name': group_data['group_name']}
  params_data = group_data.get('params')
  if (params_data):
    group['params'] = [{'key': param, 'value': params_data[param]}
                          for param in sorted(params_data.keys())];
  enable_features_data = group_data.get('enable_features')
  if enable_features_data:
    group['enable_features'] = enable_features_data
  disable_features_data = group_data.get('disable_features')
  if disable_features_data:
    group['disable_features'] = disable_features_data
  return group

def _CreateTrial(trial_name, groups):
  return {
    'name': trial_name,
    'groups': [_CreateGroup(group) for group in groups],
  }

def _FieldTrialConfigToDescription(config):
  return {
    'elements': {
      'kFieldTrialConfig': {
        'trials': [_CreateTrial(trial_name, config[trial_name])
                      for trial_name in sorted(config.keys())]
      }
    }
  }

def main(arguments):
  parser = optparse.OptionParser(
      description='Generates a struct from a JSON description.',
      usage='usage: %prog [option] -s schema description')
  parser.add_option('-b', '--destbase',
      help='base directory of generated files.')
  parser.add_option('-d', '--destdir',
      help='directory to output generated files, relative to destbase.')
  parser.add_option('-n', '--namespace',
      help='C++ namespace for generated files. e.g search_providers.')
  parser.add_option('-s', '--schema', help='path to the schema file, '
      'mandatory.')
  parser.add_option('-o', '--output', help='output filename, '
      'mandatory.')
  parser.add_option('-y', '--year',
      help='year to put in the copy-right.')
  (opts, args) = parser.parse_args(args=arguments)

  if not opts.schema:
    parser.error('You must specify a --schema.')

  description_filename = os.path.normpath(args[0])
  shortroot = opts.output
  if opts.destdir:
    output_root = os.path.join(os.path.normpath(opts.destdir), shortroot)
  else:
    output_root = shortroot

  if opts.destbase:
    basepath = os.path.normpath(opts.destbase)
  else:
    basepath = ''

  schema = _Load(opts.schema)
  description = _LoadFieldTrialConfig(description_filename)
  json_to_struct.GenerateStruct(
      basepath, output_root, opts.namespace, schema, description,
      os.path.split(description_filename)[1], os.path.split(opts.schema)[1],
      opts.year)

if __name__ == '__main__':
  main(sys.argv[1:])
