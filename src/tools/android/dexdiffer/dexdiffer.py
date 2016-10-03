#!/usr/bin/env python
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Tool to diff 2 dex files that have been proguarded.

To use this tool, first get dextra. http://newandroidbook.com/tools/dextra.html
Then invoke script like:

  PATH=$PATH:/path/to/dextra dexdiffer.py --old classes1.dex --new classes2.dex

apks files may be used as well.
"""

import argparse
import errno
import re
import subprocess
import sys
import tempfile
import zipfile


_QUALIFIERS = set(['public', 'protected', 'private', 'final', 'static',
                   'abstract', 'volatile', 'native', 'enum'])


def _IsNewClass(line):
  return line.endswith(':')


# Expects lines like one of these 3:
# 'android.support.v8.MenuPopupHelper -> android.support.v8.v:'
# '    android.view.LayoutInflater mInflater -> d'
# '    117:118:void setForceShowIcon(boolean) -> b'
# Those three examples would return
# 'android.support.v8.MenuPopupHelper', 'android.support.v8.v'
# 'android.view.LayoutInflater mInflater', 'android.view.LayoutInflater d'
# 'void setForceShowIcon(boolean)', 'void b(boolean)'
def _ParseMappingLine(line):
  line = line.rstrip(':')

  # Stripping any line number denotations
  line = re.sub(r'\d+:\d+:', '', line)
  line = re.sub(r'\):\d+', ')', line)

  original_name, new_name = line.split(' -> ')

  type_string = ''
  if ' ' in original_name:
    type_string = original_name[:original_name.find(' ') + 1]

  arguments_string = ''
  match = re.search(r'(\(.*?\))', original_name)
  if match:
    arguments_string = match.group(1)

  return original_name, type_string + new_name + arguments_string


def _ReadMappingDict(mapping_file):
  mapping = {}
  renamed_class_name = ''
  original_class_name = ''
  current_entry = []
  for line in mapping_file:
    line = line.strip()
    if _IsNewClass(line):
      if renamed_class_name:
        mapping[renamed_class_name] = current_entry

      member_mappings = {}
      original_class_name, renamed_class_name = _ParseMappingLine(line)
      current_entry = [original_class_name, member_mappings]
    else:
      original_member_name, renamed_member_name = _ParseMappingLine(line)
      member_mappings[renamed_member_name] = original_member_name

  if current_entry and renamed_class_name:
    mapping[renamed_class_name] = current_entry
  return mapping


def _StripComments(string):
  # Remove all occurances of multiline comments (/*COMMENT*/)
  string = re.sub(r'/\*.*?\*/', "", string, flags=re.DOTALL)
  # Remove all occurances of single line comments (//COMMENT)
  string = re.sub(r'//.*?$', "", string)
  return string


def _StripQuotes(string):
  return re.sub(r'([\'"]).*?\1', '', string)


def _RemoveQualifiers(string_tokens):
  while string_tokens and string_tokens[0] in _QUALIFIERS:
    string_tokens = string_tokens[1:]
  return string_tokens


def _GetLineTokens(line):
  line = _StripComments(line)
  # Match all alphanumeric + underscore with \w then cases for:
  # '$', '<', '>', '{', '}', '[', ']', and '.'
  tokens = re.findall(r'[\w\$\.<>\{\}\[\]]+', line)
  return _RemoveQualifiers(tokens)


def _IsClassDefinition(line_tokens):
  return line_tokens and line_tokens[0] == 'class'


def _IsEndOfClass_definition(line_tokens):
  return line_tokens and line_tokens[-1] == '{'


def _IsEndOfClass(line_tokens):
  return line_tokens and line_tokens[-1] == '}'


def _TypeLookup(renamed_type, mapping_dict):
  renamed_type_stripped = renamed_type.strip('[]')
  postfix = renamed_type.replace(renamed_type_stripped, '')

  if renamed_type_stripped in mapping_dict:
    real_type = mapping_dict[renamed_type_stripped][0]
  else:
    real_type = renamed_type_stripped

  return real_type + postfix


def _GetMemberIdentifier(line_tokens, mapping_dict, renamed_class_name,
                         is_function):
  assert len(line_tokens) > 1
  if mapping_dict:
    assert renamed_class_name in mapping_dict
    mapping_entry = mapping_dict[renamed_class_name][1]

  renamed_type = line_tokens[0]
  real_type = _TypeLookup(renamed_type, mapping_dict)

  renamed_name_token = line_tokens[1]
  renamed_name_token, _, _ = renamed_name_token.partition('=')

  function_args = ''
  if is_function:
    function_args += '('
    for token in line_tokens[2:]:
      function_args += _TypeLookup(token, mapping_dict) + ','
    # Remove trailing ','
    function_args = function_args.rstrip(',')
    function_args += ')'

  renamed_member_identifier = (real_type + ' ' + renamed_name_token
                               + function_args)

  if not mapping_dict:
    return renamed_member_identifier

  if renamed_member_identifier not in mapping_entry:
    print 'Proguarded class which caused the issue:', renamed_class_name
    print 'Key supposed to be in this dict:',  mapping_entry
    print 'Definition line tokens:', line_tokens

  # This will be the real type + real_identifier + any real function args (if
  # applicable)
  return mapping_entry[renamed_member_identifier]


def _GetClassNames(line_tokens, mapping_dict):
  assert len(line_tokens) > 1
  if not mapping_dict:
    return line_tokens[1], line_tokens[1]
  assert line_tokens[1] in mapping_dict
  return line_tokens[1], mapping_dict[line_tokens[1]][0]


def _IsLineFunctionDefinition(line):
  line = _StripComments(line)
  line = _StripQuotes(line)
  return line.find('(') > 0 and line.find(')') > 0


# Expects data from dextra -j -m -f
# Returns dictionary mapping class name to list of members
def _BuildMappedDexDict(dextra_file, mapping_dict):
  # Have to add 'bool' -> 'boolean' mapping in dictionary, since for some reason
  # dextra shortens boolean to bool.
  if mapping_dict:
    mapping_dict['bool'] = ['boolean', {}]
  dex_dict = {}
  current_entry = []
  reading_class_header = True
  unmatched_string = False

  for line in dextra_file:
    # Accounting for multi line strings
    if line.count('"') % 2:
      unmatched_string = not unmatched_string
      continue
    if unmatched_string:
      continue

    line_tokens = _GetLineTokens(line)
    if _IsClassDefinition(line_tokens):
      reading_class_header = True
      renamed_class_name, real_class_name = _GetClassNames(line_tokens,
                                                           mapping_dict)
    if _IsEndOfClass_definition(line_tokens):
      reading_class_header = False
      continue
    if _IsEndOfClass(line_tokens):
      dex_dict[real_class_name] = current_entry
      current_entry = []
      continue

    if not reading_class_header and line_tokens:
      is_function = _IsLineFunctionDefinition(line)
      member = _GetMemberIdentifier(line_tokens, mapping_dict,
                                    renamed_class_name, is_function)
      current_entry.append(member)

  return dex_dict


def _DiffDexDicts(dex_base, dex_new):
  diffs = []
  for key, base_class_members in dex_base.iteritems():
    if key in dex_new:
      # Class in both
      base_class_members_set = set(base_class_members)
      # Removing from dex_new to have just those which only appear in dex_new
      # left over.
      new_class_members_set = set(dex_new.pop(key))
      if base_class_members_set == new_class_members_set:
        continue
      else:
        # They are not equal
        diff_string = key
        for diff in base_class_members_set.difference(new_class_members_set):
          # Base has stuff the new one doesn't
          diff_string += '\n' + '-  ' + diff
        for diff in new_class_members_set.difference(base_class_members_set):
          # New has stuff the base one doesn't
          diff_string += '\n' + '+  ' + diff
        diffs.append(diff_string)
    else:
      # Class not found in new
      diff_string = '-class ' + key
      diffs.append(diff_string)
  if dex_new:
    # Classes in new that have yet to be hit by base
    for key in dex_new:
      diff_string = '+class ' + key
      diffs.append(diff_string)

  return diffs


def _RunDextraOnDex(dex_path):
  try:
    out = subprocess.check_output(
        ['dextra.ELF64', '-j', '-f', '-m', dex_path])
    return out.splitlines()
  except OSError as e:
    if e.errno == errno.ENOENT:
      raise Exception('Ensure dextra.ELF64 is in your PATH')
    raise


def _RunDextra(dex_or_apk_path):
  if dex_or_apk_path.endswith('.dex'):
    return _RunDextraOnDex(dex_or_apk_path)

  with tempfile.NamedTemporaryFile(suffix='.dex') as tmp_file:
    with zipfile.ZipFile(dex_or_apk_path) as apk:
      tmp_file.write(apk.read('classes.dex'))
      tmp_file.flush()
    return _RunDextraOnDex(tmp_file.name)


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('--base-mapping-file',
                      help='Mapping file from proguard output for base dex')
  parser.add_argument('--base-dextra-output',
                      help='dextra -j -f -m output for base dex')
  parser.add_argument('--new-mapping-file',
                      help='Mapping file from proguard output for new dex')
  parser.add_argument('--new-dextra-output',
                      help='dextra -j -f -m output for new dex')
  parser.add_argument('--old',
                      help='Path to base apk / classes.dex')
  parser.add_argument('--new',
                      help='Path to new apk / classes.dex')
  args = parser.parse_args()

  mapping_base = {}
  mapping_new = {}
  if args.base_mapping_file:
    with open(args.base_mapping_file) as f:
      mapping_base = _ReadMappingDict(f)
  if args.new_mapping_file:
    with open(args.new_mapping_file) as f:
      mapping_new = _ReadMappingDict(f)

  if args.base_dextra_output:
    with open(args.base_dextra_output) as f:
      dex_base = _BuildMappedDexDict(f, mapping_base)
  else:
    assert args.old, 'Must pass either --old or --base-dextra-output'
    print 'Running dextra #1'
    lines = _RunDextra(args.old)
    dex_base = _BuildMappedDexDict(lines, mapping_base)
  if args.new_dextra_output:
    with open(args.new_dextra_output) as f:
      dex_new = _BuildMappedDexDict(f, mapping_new)
  else:
    assert args.new, 'Must pass either --new or --new-dextra-output'
    print 'Running dextra #2'
    lines = _RunDextra(args.new)
    dex_new = _BuildMappedDexDict(lines, mapping_base)

  print 'Analyzing...'
  diffs = _DiffDexDicts(dex_base, dex_new)
  if diffs:
    for diff in diffs:
      print diff
    sys.exit(1)
  else:
    class_count = len(dex_base)
    method_count = sum(len(v) for v in dex_base.itervalues())
    print ('No meaningful differences: '
           'both have the same %d classes and %d methods.' %
           (class_count, method_count))


if __name__ == '__main__':
  main()

