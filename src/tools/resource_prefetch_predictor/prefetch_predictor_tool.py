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
import operator
import sqlite3

from resource_prefetch_predictor_pb2 import ResourceData


class Entry(object):
  """Represents an entry in the predictor database."""
  def __init__(
      self, main_page_url, resource_url, proto_buffer):
    self.main_page_url = main_page_url
    self.resource_url = resource_url
    self.proto = ResourceData()
    self.proto.ParseFromString(proto_buffer)
    self.confidence = float(self.proto.number_of_hits / (
        self.proto.number_of_hits + self.proto.number_of_misses))
    self.score = self._Score()

  def _Score(self):
    """Mirrors ResourcePrefetchPredictorTables::ComputeResourceScore."""
    priority_multiplier = 1
    type_multiplier = 1

    if self.proto.priority == ResourceData.REQUEST_PRIORITY_HIGHEST:
      priority_multiplier = 3
    elif self.proto.priority == ResourceData.REQUEST_PRIORITY_MEDIUM:
      priority_multiplier = 2

    if self.proto.resource_type in (ResourceData.RESOURCE_TYPE_STYLESHEET,
                                    ResourceData.RESOURCE_TYPE_SCRIPT):
      type_multiplier = 3
    elif self.proto.resource_type == ResourceData.RESOURCE_TYPE_FONT_RESOURCE:
      type_multiplier = 2

      return (100 * (priority_multiplier * 100 + type_multiplier * 10)
              - self.proto.average_position)

  @classmethod
  def FromRow(cls, row):
    """Builds an entry from a database row."""
    return Entry(*row)

  def __str__(self):
    return 'score: %s\nmain_page_url: %s\nconfidence: %f"\n%s' % (
        self.score, self.main_page_url, self.confidence, self.proto)


def FilterAndSort(entries, domain):
  """Filters and sorts the entries to be prefetched for a given domain.

  Uses the default thresholds defined in resource_prefetch_common.cc.
  """
  result = filter(
      lambda x: ((domain is None or x.main_page_url == domain)
                 and x.confidence > .7
                 and x.proto.number_of_hits >= 2), entries)
  return sorted(result, key=operator.attrgetter('score'), reverse=True)


def DatabaseStats(filename, domain):
  connection = sqlite3.connect(filename)
  c = connection.cursor()
  query = ('SELECT main_page_url, resource_url, proto '
           'FROM resource_prefetch_predictor_host')
  entries = [Entry.FromRow(row) for row in c.execute(query)]
  prefetched = FilterAndSort(entries, domain)
  for x in prefetched:
    print x


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('-f', dest='database_filename', required=True,
                      help='Path to the database')
  parser.add_argument('-d', dest='domain', default=None, help='Domain')
  args = parser.parse_args()
  DatabaseStats(args.database_filename, args.domain)


if __name__ == '__main__':
  main()
