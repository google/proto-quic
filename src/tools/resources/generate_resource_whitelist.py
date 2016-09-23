#!/usr/bin/env python
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import argparse
import os
import re
import sys

USAGE = """generate_resource_whitelist.py [-h] [-i INPUT] [-o OUTPUT]

INPUT specifies a file containing existing resource IDs that should be
whitelisted, where each line of INPUT contains a single resource ID.

Creates a resource whitelist by collecting existing resource IDs that are part
of unknown pragma warnings and adds additional arch specfic resource IDs.

This script is used to find the resources that are actually compiled in Chrome
in order to only include the needed strings/images in Chrome PAK files.
These resource IDs show up in the build output after building Chrome with
gn variable enable_resource_whitelist_generation set to true.
This causes the compiler to print out an UnknownPragma message every time a
resource ID is used.

E.g. foo.cc:22:0: warning: ignoring #pragma whitelisted_resource_12345
[-Wunknown-pragmas]

On Windows, the message is simply a message via __pragma(message(...)).

"""

COMPONENTS_STRINGS_HEADER = 'gen/components/strings/grit/components_strings.h'

# We don't want the resources are different between 32-bit and 64-bit build,
# added arch related resources even they are not used.
ARCH_SPECIFIC_RESOURCES = [
  'IDS_VERSION_UI_64BIT',
  'IDS_VERSION_UI_32BIT',
]


def _FindResourceIds(header, resource_names):
  """Returns the numerical resource IDs that correspond to the given resource
     names, as #defined in the given header file."
  """
  pattern = re.compile(
      r'^#define (%s) _Pragma\S+ (\d+)$' % '|'.join(resource_names))
  with open(header, 'r') as f:
    res_ids = [ int(pattern.match(line).group(2))
                 for line in f if pattern.match(line) ]
  if len(res_ids) != len(resource_names):
    raise Exception('Find resource id failed: the result is ' +
                    ', '.join(str(i) for i in res_ids))
  return set(res_ids)


# TODO(estevenson): Remove this after updating official build scripts.
def _GetResourceIdsInPragmaWarnings(input):
   """Returns set of resource ids that are inside unknown pragma warnings
      for the given input.
   """
   used_resources = set()
   unknown_pragma_warning_pattern = re.compile(
       'whitelisted_resource_(?P<resource_id>[0-9]+)')
   for ln in input:
     match = unknown_pragma_warning_pattern.search(ln)
     if match:
       resource_id = int(match.group('resource_id'))
       used_resources.add(resource_id)
   return used_resources


def main():
  parser = argparse.ArgumentParser(usage=USAGE)
  parser.add_argument(
      '-i', '--input', type=argparse.FileType('r'), default=sys.stdin,
      help='A resource whitelist where each line contains one resource ID')
  parser.add_argument(
      '-o', '--output', type=argparse.FileType('w'), default=sys.stdout,
      help='The resource list path to write (default stdout)')
  parser.add_argument(
      '--out-dir', required=True,
      help='The out target directory, for example out/Release')
  parser.add_argument(
      '--use-existing-resource-ids', action='store_true', default=False,
      help='Specifies that the input file already contains resource ids')

  args = parser.parse_args()

  used_resources = set()
  if args.use_existing_resource_ids:
    used_resources.update([int(resource_id) for resource_id in args.input])
  else:
    used_resources.update(_GetResourceIdsInPragmaWarnings(args.input))

  used_resources |= _FindResourceIds(
      os.path.join(args.out_dir, COMPONENTS_STRINGS_HEADER),
      ARCH_SPECIFIC_RESOURCES)

  for resource_id in sorted(used_resources):
    args.output.write('%d\n' % resource_id)

if __name__ == '__main__':
  main()
