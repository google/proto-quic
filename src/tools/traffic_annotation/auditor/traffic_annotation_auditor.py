#!/usr/bin/env python
# Copyright (c) 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""This script is used to extract network traffic annotations from Chrome.
Please refer to README.md for running steps."""

import argparse
import os
import subprocess
import sys

# These two lines are required to import protobuf from third_party directory
# instead of the one installed with python.
from prepare_protobuf import PrepareProtobuf
PrepareProtobuf()

from google.protobuf import text_format
import traffic_annotation_pb2


def _RunClangTool(src_dir, build_dir, path_filters):
  """Executes the clang tool to extract annotations.
  Args:
    src_dir: str Path to the src directory of Chrome.
    build_dir: str Path to the build directory.
    path_filters: list of str List of paths to source directories for
        extraction.

  Returns:
    raw_annotations: str Output of clang tool (extracted content and metadata of
        annotations).
  """
  raw_annotations = ""
  for path in path_filters:
    args = [
        src_dir + "/tools/clang/scripts/run_tool.py",
        "--generate-compdb",
        "traffic_annotation_extractor",
        build_dir, path]
    if sys.platform == "win32":
      args.insert(0, "python")
    command = subprocess.Popen(args, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    stdout_text, stderr_text = command.communicate()
    raw_annotations += stdout_text
    if stderr_text:
      print stderr_text
  return raw_annotations


def _ParsRawAnnotations(raw_annotations):
  """Parses raw annotations texts which are received from the clang tool.
  Args:
    raw_annotations: str Serialization of annotations and metadata. Each
        annotation should have the following lines:
        1- "==== NEW ANNOTATION ===="
        2- File path.
        3- Name of the function including this position.
        4- Line number.
        5- Unique id of annotation.
        6- Serialization of annotation text (several lines)
        n- "==== ANNOTATION ENDS ===="

  Returns:
    annotations: ExtractedNetworkTrafficAnnotation A protobuf including all
      extracted annotations.
    errors: list of str List of errors.
  """
  annotations = traffic_annotation_pb2.ExtractedNetworkTrafficAnnotation()
  errors = []

  lines = [line.strip("\r\n") for line in raw_annotations.split("\n")]
  current = 0

  try:
    while current < len(lines) - 1:
      if lines[current] != "==== NEW ANNOTATION ====":
        raise Exception(
            "Error at line %i, expected starting new annotaion." % current)
      if current + 5 >= len(lines):
        raise Exception(
            "Not enough header lines at line %i." % current)

      # Extract header lines.
      source = traffic_annotation_pb2.NetworkTrafficAnnotation.TrafficSource()
      source.file = lines[current + 1]
      source.function = lines[current + 2]
      source.line = int(lines[current + 3])
      unique_id = lines[current + 4]

      # Extract serialized proto.
      current += 5
      annotation_text = ""

      while current < len(lines):
        current += 1
        if lines[current - 1] == "==== ANNOTATION ENDS ====":
          break
        else:
          annotation_text += lines[current - 1]
      else:
        raise Exception(
          "Error at line %i, expected annotation end tag." % current)

      # Process unittests and undefined tags.
      if unique_id == "UnitTest":
        continue
      if unique_id == "Undefined":
        errors.append("Annotation is not defined for file '%s', line %i." %
            (source.file, source.line))
        continue

      # Decode serialized proto.
      annotation_proto = traffic_annotation_pb2.NetworkTrafficAnnotation()
      try:
        text_format.Parse(annotation_text, annotation_proto)
      except Exception as error:
        errors.append("Annotation in file '%s', line %i, has error: %s" %
            (source.file, source.line, error))

      # Add new proto.
      annotation_proto.unique_id = unique_id
      annotation_proto.source.CopyFrom(source)
      annotations.network_traffic_annotation.add().CopyFrom(annotation_proto)

  except Exception as error:
    errors.append(str(error))

  print "Extracted %i annotations with %i errors." % \
    (len(annotations.network_traffic_annotation), len(errors))
  return annotations, errors


def _WriteSummaryFile(annotations, errors, file_path):
  """Writes extracted annotations and errors into a simple text file.
  args:
    annotations ExtractedNetworkTrafficAnnotation A protobuf including all
      extracted annotations.
    errors list of str List of all extraction errors.
    file_path str File path to the brief summary file.
  """
  with open(file_path, 'w') as summary_file:
    if errors:
      summary_file.write("Errors:\n%s\n\n" % "\n".join(errors))
    if len(annotations.network_traffic_annotation):
      summary_file.write("Annotations:\n%s" % "\n---\n".join(
          [str(a) for a in annotations.network_traffic_annotation]))


def main():
  parser = argparse.ArgumentParser(description='Traffic Annotation Auditor.')
  parser.add_argument('--build-dir',
                      help='Path to the build directory.')
  parser.add_argument('--extractor-output',
                      help='Optional path to the temporary file that extracted '
                           'annotations will be stored into.')
  parser.add_argument('--extractor-input',
                      help='Optional path to the file that temporary extracted '
                           'annotations are already stored in. If this is '
                           'provided, clang tool is not run and this is used '
                           'as input.')
  parser.add_argument('--summary-file',
                      help='Path to the output file.')
  parser.add_argument('path_filters',
                      nargs='*',
                      help='Optional paths to filter what files the tool is '
                           'run on.')
  args = parser.parse_args()

  if not args.summary_file:
    print "Warning: Output file not specified."

  # If a pre-extracted input file is provided, load it.
  if args.extractor_input:
    with open(args.extractor_input, 'r') as raw_file:
      raw_annotations = raw_file.read()
  else:
    # Either extacted input file or build directory should be provided.
    if not args.build_dir:
      print "You must either specify the build directory to run the clang " \
            "tool and extract annotations, or specify the input directory " \
            "where extracted annotation files already exist.\n"
      return 1

    # Get Chrome source directory with relative path from this file.
    chrome_source = os.path.abspath(os.path.join(os.path.dirname(
        os.path.realpath(__file__)), "..", "..", ".."))
    raw_annotations = _RunClangTool(chrome_source, args.build_dir,
        args.path_filters if args.path_filters else ["./"])

  if args.extractor_output:
    with open(args.extractor_output, 'w') as raw_file:
      raw_file.write(raw_annotations)

  annotations, errors = _ParsRawAnnotations(raw_annotations)

  if not annotations:
    print "Could not extract any annotation."
    if errors:
      print "Errors:\n%s" % "\n".join(errors)
    return 1

  if args.summary_file:
    _WriteSummaryFile(annotations, errors, args.summary_file)

  return 0


if __name__ == '__main__':
  sys.exit(main())
