#!/usr/bin/env python
# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""A utility for generating builder classes for UKM entries.

It takes as input a ukm.xml file describing all of the entries and metrics,
and produces a c++ header and implementation file exposing builders for those
entries and metrics.
"""


import argparse
import logging
import os
import re
import sys

import model


HEADER = """
// Generated from gen_builders.py.  DO NOT EDIT!
// source: ukm.xml

#ifndef SERVICES_METRICS_PUBLIC_CPP_UKM_BUILDERS_H
#define SERVICES_METRICS_PUBLIC_CPP_UKM_BUILDERS_H

#include <map>

#include "services/metrics/public/cpp/ukm_entry_builder_base.h"

namespace ukm {{
namespace builders {{

{decls}

typedef std::map<uint64_t, const char*> DecodeMap;
DecodeMap CreateDecodeMap();

}}  // namespace builders
}}  // namespace ukm

#endif  // SERVICES_METRICS_PUBLIC_CPP_UKM_BUILDERS_H
"""

BODY = """
// Generated from gen_builders.py.  DO NOT EDIT!
// source: ukm.xml

#include "services/metrics/public/cpp/ukm_builders.h"

#include "base/metrics/metrics_hashes.h"

namespace ukm {{
namespace builders {{

{impls}

std::map<uint64_t, const char*> CreateDecodeMap() {{
  return {{
    {decodes}
  }};
}}

}}  // namespace builders
}}  // namespace ukm
"""

BUILDER_DECL = """
class {name} : public ::ukm::internal::UkmEntryBuilderBase {{
 public:
  {name}(ukm::SourceId source_id);
  ~{name}() override;

  static const char kEntryName[];

{setters}
}};
"""

SETTER_DECL = """
  static const char k{metric}Name[];
  {name}& Set{metric}(int64_t value);
"""

BUILDER_IMPL = """
const char {name}::kEntryName[] = "{raw}";

{name}::{name}(ukm::SourceId source_id) :
  ::ukm::internal::UkmEntryBuilderBase(
      source_id,
      base::HashMetricName(kEntryName)) {{
}}

{name}::~{name}() = default;

{setters}
"""

SETTER_IMPL = """
const char {name}::k{metric}Name[] = "{raw}";

{name}& {name}::Set{metric}(int64_t value) {{
  AddMetric(base::HashMetricName(k{metric}Name), value);
  return *this;
}}
"""

ENTRY_DECODE = """
    {{base::HashMetricName({name}::kEntryName), {name}::kEntryName}},
    {metric_decodes}
"""

METRIC_DECODE = """
    {{base::HashMetricName({name}::k{metric}Name), {name}::k{metric}Name}},
"""

parser = argparse.ArgumentParser(description='Generate UKM entry builders')
parser.add_argument('--input', help='Path to ukm.xml')
parser.add_argument('--output', help='Path to generated directory')

def sanitize_name(name):
  s = re.sub('[^0-9a-zA-Z_]', '_', name)
  return s

def GetSetterDecl(builder_name, metric):
  metric_name = sanitize_name(metric['name'])
  return SETTER_DECL.format(name=builder_name, metric=metric_name)

def GetBuilderDecl(event):
  builder_name = sanitize_name(event['name'])
  setters = "".join(GetSetterDecl(builder_name, metric)
                    for metric in event['metrics'])
  return BUILDER_DECL.format(name=builder_name, setters=setters)

def GetHeader(data):
  decls = "\n".join(GetBuilderDecl(event) for event in data['events'])
  return HEADER.format(decls=decls)

def WriteHeader(outdir, data):
  output = open(os.path.join(outdir, "ukm_builders.h"), 'w')
  output.write(GetHeader(data))

def GetSetterImpl(builder_name, metric):
  metric_name = sanitize_name(metric['name'])
  return SETTER_IMPL.format(name=builder_name, metric=metric_name,
                            raw=metric['name'])

def GetBuilderImpl(event):
  builder_name = sanitize_name(event['name'])
  setters = "\n".join(GetSetterImpl(builder_name, metric)
                      for metric in event['metrics'])
  return BUILDER_IMPL.format(name=builder_name, raw=event['name'],
                             setters=setters)

def WriteBody(outdir, data):
  output = open(os.path.join(outdir, "ukm_builders.cc"), 'w')
  output.write(GetBody(data))

def GetMetricDecode(builder_name, metric):
  metric_name = sanitize_name(metric['name'])
  return METRIC_DECODE.format(name=builder_name, metric=metric_name)

def GetEntryDecode(event):
  builder_name = sanitize_name(event['name'])
  metric_decodes = "\n".join(GetMetricDecode(builder_name, metric)
                             for metric in event['metrics'])
  return ENTRY_DECODE.format(name=builder_name,
                             metric_decodes=metric_decodes)

def GetBody(data):
  impls = "\n".join(GetBuilderImpl(event) for event in data['events'])
  decodes = "\n".join(GetEntryDecode(event) for event in data['events'])
  return BODY.format(impls=impls, decodes=decodes)


def main(argv):
  args = parser.parse_args()
  data = model.UKM_XML_TYPE.Parse(open(args.input).read())
  WriteHeader(args.output, data)
  WriteBody(args.output, data)
  return 0

if '__main__' == __name__:
  sys.exit(main(sys.argv))
