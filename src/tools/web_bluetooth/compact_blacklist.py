#!/usr/bin/env python
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Script for converting the Web Bluetooth GATT blacklist into the format
expected by ContentBrowserClient#GetWebBluetoothBlacklist.

See:
https://github.com/WebBluetoothCG/registries/blob/master/gatt_blacklist.txt
content/public/browser/content_browser_client.h

Usage:
  compact_blacklist.py <gatt_blacklist.txt>
"""

import collections
import string
import sys

UUID_LENGTH = 36
UUID_BASE_POSTFIX = '-0000-1000-8000-00805f9b34fb'


class BadLineException(Exception):
  pass


class InvalidUUIDException(Exception):
  pass


class DuplicateUUIDException(Exception):
  pass


class InvalidExclusionException(Exception):
  pass


def ValidUUID(uuid):
  if len(uuid) != UUID_LENGTH:
    return False
  for i in range(UUID_LENGTH):
    if i in [8, 13, 18, 23]:
      if uuid[i] != '-':
        return False
    else:
      if uuid[i] not in string.hexdigits:
        return False
  return True




def ShortenUUID(uuid):
  """Shorten a UUUD that use Bluetooth base UUID.

  Note: this function shortens all UUIDs that use the Bluetooth base
  UUID even though the specification states that only an assigned UUID
  can be shortened. In this case it works fine, since the constructor in
  bluetooth_uuid.cc also works the same way.
  """

  if uuid[8:] == UUID_BASE_POSTFIX:
    new_uuid = '%x' % int(uuid[:8], 16)
    if len(new_uuid) in [4, 8]:
      uuid = new_uuid
  return uuid


def Process(line, blacklist):
  line = line.strip().lower()
  if not line or line.startswith('#'):
    return
  fields = line.split()
  if len(fields) not in [1, 2]:
    raise BadLineException('Badly formatted line: %s' % line)
  uuid = fields[0]
  if not ValidUUID(uuid):
    raise InvalidUUIDException('Invalid UUID: %s' % line)
  uuid = ShortenUUID(uuid)
  if uuid in blacklist:
    raise DuplicateUUIDException('Duplicate UUID: %s' % line)
  if len(fields) == 1:
    blacklist[uuid] = 'e'
  elif fields[1] == 'exclude-writes':
    blacklist[uuid] = 'w'
  elif fields[1] == 'exclude-reads':
    blacklist[uuid] = 'r'
  else:
    raise InvalidExclusionException('Invalid exclusion value: %s' % line)


def main():
  if len(sys.argv) != 2:
    print('Usage: %s <gatt_blacklist.txt>' % sys.argv[0])
    return 1

  try:
    blacklist = collections.OrderedDict()
    with open(sys.argv[1]) as f:
      for line in f:
        Process(line, blacklist)
    print(','.join('%s:%s' % (uuid, blacklist[uuid]) for uuid in blacklist))
    return 0
  except Exception as e:
    print('Failed to compact blacklist. %s' % e)
    return 1


if __name__ == '__main__':
  sys.exit(main())
