#!/usr/bin/python
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Inspection of the prefetch predictor database.

On Android, the database can be extracted using:
adb pull \
  '/data/user/0/$package_name/app_chrome/Default/Network Action Predictor'
  predictor_db
"""

import argparse
import sqlite3
import os

from resource_prefetch_predictor_pb2 import (PrefetchData, ResourceData)


class Entry(object):
  """Represents an entry in the predictor database."""
  def __init__(
      self, primary_key, proto_buffer):
    self.primary_key = primary_key
    self.prefetch_data = PrefetchData()
    self.prefetch_data.ParseFromString(proto_buffer)

  @classmethod
  def _ComputeResourceScore(cls, resource):
    """Mirrors ResourcePrefetchPredictorTables::ComputeResourceScore.

    Args:
      resource: ResourceData.

    Return:
      The resource score (int).
    """
    priority_multiplier = 1
    type_multiplier = 1

    if resource.priority == ResourceData.REQUEST_PRIORITY_HIGHEST:
      priority_multiplier = 3
    elif resource.priority == ResourceData.REQUEST_PRIORITY_MEDIUM:
      priority_multiplier = 2

    if resource.resource_type in (ResourceData.RESOURCE_TYPE_STYLESHEET,
                                  ResourceData.RESOURCE_TYPE_SCRIPT):
      type_multiplier = 3
    elif resource.resource_type == ResourceData.RESOURCE_TYPE_FONT_RESOURCE:
      type_multiplier = 2

    return (100 * (priority_multiplier * 100 + type_multiplier * 10)
            - resource.average_position)

  @classmethod
  def FromRow(cls, row):
    """Builds an entry from a database row."""
    return Entry(*row)

  @classmethod
  def _PrettyPrintResource(cls, resource):
    """Pretty-prints a resource to stdout.

    Args:
      resource: ResourceData.
    """
    print 'score: %d' % cls._ComputeResourceScore(resource)
    print resource

  def PrettyPrintCandidates(self):
    """Prints the candidates for prefetch."""
    print 'primary_key: %s' % self.prefetch_data.primary_key
    for resource in self.prefetch_data.resources:
      confidence = float(resource.number_of_hits) / (
          resource.number_of_hits + resource.number_of_misses)
      if resource.number_of_hits < 2 or confidence < .7:
        continue
      self._PrettyPrintResource(resource)

# The version of python sqlite3 library we have in Ubuntu 14.04 LTS doesn't
# support views but command line util does.
# TODO(alexilin): get rid of this when python sqlite3 adds view support.
def CreateCompatibleDatabaseCopy(filename):
  import tempfile, shutil, subprocess
  _, tmpfile = tempfile.mkstemp()
  shutil.copy2(filename, tmpfile)
  subprocess.call(['sqlite3', tmpfile, 'DROP VIEW MmapStatus'])
  return tmpfile

def DatabaseStats(filename, domain):
  connection = sqlite3.connect(filename)
  c = connection.cursor()
  query = ('SELECT key, proto FROM resource_prefetch_predictor_host')
  entries = [Entry.FromRow(row) for row in c.execute(query)]
  for x in entries:
    if domain is None or x.primary_key == domain:
      x.PrettyPrintCandidates()


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('-f', dest='database_filename', required=True,
                      help='Path to the database')
  parser.add_argument('-d', dest='domain', default=None, help='Domain')
  args = parser.parse_args()
  try:
    database_copy = CreateCompatibleDatabaseCopy(args.database_filename)
    DatabaseStats(database_copy, args.domain)
  finally:
    if os.path.exists(database_copy):
      os.remove(database_copy)


if __name__ == '__main__':
  main()
