#!/usr/bin/env python
# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Support for formatting a data pack file used for platform agnostic resource
files.
"""

import collections
import exceptions
import os
import struct
import sys
if __name__ == '__main__':
  sys.path.append(os.path.join(os.path.dirname(__file__), '../..'))

from grit import util
from grit.node import include
from grit.node import message
from grit.node import structure


PACK_FILE_VERSION = 4
HEADER_LENGTH = 2 * 4 + 1  # Two uint32s. (file version, number of entries) and
                           # one uint8 (encoding of text resources)
BINARY, UTF8, UTF16 = range(3)


class WrongFileVersion(Exception):
  pass


DataPackContents = collections.namedtuple(
    'DataPackContents', 'resources encoding')


def Format(root, lang='en', output_dir='.'):
  """Writes out the data pack file format (platform agnostic resource file)."""
  data = {}
  for node in root.ActiveDescendants():
    with node:
      if isinstance(node, (include.IncludeNode, message.MessageNode,
                           structure.StructureNode)):
        id, value = node.GetDataPackPair(lang, UTF8)
        if value is not None:
          data[id] = value
  return WriteDataPackToString(data, UTF8)


def ReadDataPack(input_file):
  """Reads a data pack file and returns a dictionary."""
  data = util.ReadFile(input_file, util.BINARY)
  original_data = data

  # Read the header.
  version, num_entries, encoding = struct.unpack('<IIB', data[:HEADER_LENGTH])
  if version != PACK_FILE_VERSION:
    print 'Wrong file version in ', input_file
    raise WrongFileVersion

  resources = {}
  if num_entries == 0:
    return DataPackContents(resources, encoding)

  # Read the index and data.
  data = data[HEADER_LENGTH:]
  kIndexEntrySize = 2 + 4  # Each entry is a uint16 and a uint32.
  for _ in range(num_entries):
    id, offset = struct.unpack('<HI', data[:kIndexEntrySize])
    data = data[kIndexEntrySize:]
    next_id, next_offset = struct.unpack('<HI', data[:kIndexEntrySize])
    resources[id] = original_data[offset:next_offset]

  return DataPackContents(resources, encoding)


def WriteDataPackToString(resources, encoding):
  """Returns a string with a map of id=>data in the data pack format."""
  ids = sorted(resources.keys())
  ret = []

  # Write file header.
  ret.append(struct.pack('<IIB', PACK_FILE_VERSION, len(ids), encoding))
  HEADER_LENGTH = 2 * 4 + 1            # Two uint32s and one uint8.

  # Each entry is a uint16 + a uint32s. We have one extra entry for the last
  # item.
  index_length = (len(ids) + 1) * (2 + 4)

  # Write index.
  data_offset = HEADER_LENGTH + index_length
  for id in ids:
    ret.append(struct.pack('<HI', id, data_offset))
    data_offset += len(resources[id])

  ret.append(struct.pack('<HI', 0, data_offset))

  # Write data.
  for id in ids:
    ret.append(resources[id])
  return ''.join(ret)


def WriteDataPack(resources, output_file, encoding):
  """Writes a map of id=>data into output_file as a data pack."""
  content = WriteDataPackToString(resources, encoding)
  with open(output_file, 'wb') as file:
    file.write(content)


def RePack(output_file, input_files, whitelist_file=None,
           suppress_removed_key_output=False):
  """Write a new data pack file by combining input pack files.

  Args:
      output_file: path to the new data pack file.
      input_files: a list of paths to the data pack files to combine.
      whitelist_file: path to the file that contains the list of resource IDs
                      that should be kept in the output file or None to include
                      all resources.
      suppress_removed_key_output: allows the caller to suppress the output from
                                   RePackFromDataPackStrings.

  Raises:
      KeyError: if there are duplicate keys or resource encoding is
      inconsistent.
  """
  input_data_packs = [ReadDataPack(filename) for filename in input_files]
  whitelist = None
  if whitelist_file:
    whitelist = util.ReadFile(whitelist_file, util.RAW_TEXT).strip().split('\n')
    whitelist = set(map(int, whitelist))
  resources, encoding = RePackFromDataPackStrings(
      input_data_packs, whitelist, suppress_removed_key_output)
  WriteDataPack(resources, output_file, encoding)


def RePackFromDataPackStrings(inputs, whitelist,
                              suppress_removed_key_output=False):
  """Returns a data pack string that combines the resources from inputs.

  Args:
      inputs: a list of data pack strings that need to be combined.
      whitelist: a list of resource IDs that should be kept in the output string
                 or None to include all resources.
      suppress_removed_key_output: Do not print removed keys.

  Returns:
      DataPackContents: a tuple containing the new combined data pack and its
                        encoding.

  Raises:
      KeyError: if there are duplicate keys or resource encoding is
      inconsistent.
  """
  resources = {}
  encoding = None
  for content in inputs:
    # Make sure we have no dups.
    duplicate_keys = set(content.resources.keys()) & set(resources.keys())
    if duplicate_keys:
      raise exceptions.KeyError('Duplicate keys: ' + str(list(duplicate_keys)))

    # Make sure encoding is consistent.
    if encoding in (None, BINARY):
      encoding = content.encoding
    elif content.encoding not in (BINARY, encoding):
      raise exceptions.KeyError('Inconsistent encodings: ' + str(encoding) +
                                ' vs ' + str(content.encoding))

    if whitelist:
      whitelisted_resources = dict([(key, content.resources[key])
                                    for key in content.resources.keys()
                                    if key in whitelist])
      resources.update(whitelisted_resources)
      removed_keys = [key for key in content.resources.keys()
                      if key not in whitelist]
      if not suppress_removed_key_output:
        for key in removed_keys:
          print 'RePackFromDataPackStrings Removed Key:', key
    else:
      resources.update(content.resources)

  # Encoding is 0 for BINARY, 1 for UTF8 and 2 for UTF16
  if encoding is None:
    encoding = BINARY
  return DataPackContents(resources, encoding)


# Temporary hack for external programs that import data_pack.
# TODO(benrg): Remove this.
class DataPack(object):
  pass
DataPack.ReadDataPack = staticmethod(ReadDataPack)
DataPack.WriteDataPackToString = staticmethod(WriteDataPackToString)
DataPack.WriteDataPack = staticmethod(WriteDataPack)
DataPack.RePack = staticmethod(RePack)


def main():
  # Write a simple file.
  data = {1: '', 4: 'this is id 4', 6: 'this is id 6', 10: ''}
  WriteDataPack(data, 'datapack1.pak', UTF8)
  data2 = {1000: 'test', 5: 'five'}
  WriteDataPack(data2, 'datapack2.pak', UTF8)
  print 'wrote datapack1 and datapack2 to current directory.'


if __name__ == '__main__':
  main()
