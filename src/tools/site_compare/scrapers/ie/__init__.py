#!/usr/bin/env python
# Copyright (c) 2011 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Selects the appropriate scraper for Internet Explorer."""


def GetScraper(version):
  """Returns the scraper module for the given version.

  Args:
    version: version string of IE, or None for most recent

  Returns:
    scrape module for given version
  """

  # Pychecker will warn that the parameter is unused; we only
  # support one version of IE at this time

  # We only have one version of the IE scraper for now
  return __import__("ie7", globals(), locals(), [''])


# if invoked rather than imported, test
if __name__ == "__main__":
  print GetScraper("7.0.5370.1").version
