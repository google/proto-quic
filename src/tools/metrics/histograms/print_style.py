# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Holds the constants for pretty printing histograms.xml."""

import os
import sys

# Import the metrics/common module for pretty print xml.
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'common'))
import pretty_print_xml

# Desired order for tag and tag attributes. The *_ATTRIBUTE_ORDER maps are also
# used to determine the validity of tag names.
# { tag_name: [attribute_name, ...] }
ATTRIBUTE_ORDER = {
    'affected-histogram': ['name'],
    'detail': [],
    'details': [],
    'enum': ['name', 'type'],
    'enums': [],
    # TODO(yiyaoliu): Remove fieldtrial related pieces when it is not used.
    'fieldtrial': ['name', 'separator', 'ordering'],
    'histogram': ['name', 'enum', 'units'],
    'histogram-configuration': ['logsource'],
    'histogram_suffixes': ['name', 'separator', 'ordering'],
    'histogram_suffixes_list': [],
    'histograms': [],
    'int': ['value', 'label'],
    'group': ['name', 'label'],
    'obsolete': [],
    'owner': [],
    'suffix': ['name', 'label'],
    'summary': [],
    'with-group': ['name'],
    'with-suffix': ['name'],
}

# Tag names for top-level nodes whose children we don't want to indent.
TAGS_THAT_DONT_INDENT = [
    'histogram-configuration',
    'histograms',
    'histogram_suffixes_list',
    'enums',
]

# Extra vertical spacing rules for special tag names.
# {tag_name: (newlines_after_open, newlines_before_close, newlines_after_close)}
TAGS_THAT_HAVE_EXTRA_NEWLINE = {
    'histogram-configuration': (2, 1, 1),
    'histograms': (2, 1, 1),
    'histogram_suffixes_list': (2, 1, 1),
    'histogram_suffixes': (1, 1, 1),
    'enums': (2, 1, 1),
    'histogram': (1, 1, 1),
    'enum': (1, 1, 1),
}

# Tags that we allow to be squished into a single line for brevity.
TAGS_THAT_ALLOW_SINGLE_LINE = ['summary', 'int', 'owner']

LOWERCASE_NAME_FN = lambda n: n.attributes['name'].value.lower()

# Tags whose children we want to alphabetize. The key is the parent tag name,
# and the value is a pair of the tag name of the children we want to sort,
# and a key function that maps each child node to the desired sort key.
TAGS_ALPHABETIZATION_RULES = {
    'histograms': ('histogram', LOWERCASE_NAME_FN),
    'enums': ('enum', LOWERCASE_NAME_FN),
    'enum': ('int', lambda n: int(n.attributes['value'].value)),
    'histogram_suffixes_list': ('histogram_suffixes', LOWERCASE_NAME_FN),
    'histogram_suffixes': ('affected-histogram', LOWERCASE_NAME_FN),
}


def GetPrintStyle():
  """Returns an XmlStyle object for pretty printing histograms."""
  return pretty_print_xml.XmlStyle(ATTRIBUTE_ORDER,
                                   TAGS_THAT_HAVE_EXTRA_NEWLINE,
                                   TAGS_THAT_DONT_INDENT,
                                   TAGS_THAT_ALLOW_SINGLE_LINE,
                                   TAGS_ALPHABETIZATION_RULES)
