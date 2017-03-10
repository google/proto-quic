# -*- coding: utf-8 -*-
# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Implements Gitiles' smart quotes.

This extention converts dumb quotes into smart quotes like Gitiles:

https://gerrit.googlesource.com/gitiles/+/master/gitiles-servlet/src/main/java/com/google/gitiles/doc/SmartQuotedExtension.java
"""

from markdown.inlinepatterns import Pattern
from markdown.extensions import Extension


class _GitilesSmartQuotesPattern(Pattern):
  """Process Gitiles' dumb->smart quotes."""

  QUOTES = {
      '"': (u'“', u'”'),
      "'": (u'‘', u'’'),
  }

  def handleMatch(self, m):
    lq, rq = self.QUOTES[m.group(2)]
    return u'%s%s%s' % (lq, m.group(3), rq)


class _GitilesSmartQuotesExtension(Extension):
  """Add Gitiles' smart quotes to Markdown."""
  def extendMarkdown(self, md, md_globals):
    md.inlinePatterns.add('gitilessmartquotes',
                          _GitilesSmartQuotesPattern(r"""(['"])([^\2]+)\2"""),
                          '<emphasis')


def makeExtension(*args, **kwargs):
  return _GitilesSmartQuotesExtension(*args, **kwargs)
