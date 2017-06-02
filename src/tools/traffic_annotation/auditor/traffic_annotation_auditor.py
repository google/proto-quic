#!/usr/bin/env python
# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""This script is used to extract network traffic annotations from Chrome.
Please refer to README.md for running steps."""

import argparse
import datetime
import os
import subprocess
import sys
import tempfile

from traffic_annotation_file_filter import TrafficAnnotationFileFilter


# These two lines are required to import protobuf from third_party directory
# instead of the one installed with python.
from prepare_protobuf import PrepareProtobuf
PrepareProtobuf()

from google.protobuf import text_format
import traffic_annotation_pb2


def _RecursiveHash(string):
  if len(string) == 1:
    return ord(string[0])
  last_character = ord(string[-1])
  string = string[:-1]
  return (_RecursiveHash(string) * 31 + last_character) % 138003713


def _ComputeStringHash(unique_id):
  """Computes the hash value of a string, as in
  'net/traffic_annotation/network_traffic_annotation.h'.
  args:
    unique_id: str The string to be converted to hash code.

  Returns:
    unsigned int Hash code of the input string
  """
  return _RecursiveHash(unique_id) if len(unique_id) else -1


def _RunClangTool(src_dir, build_dir, path_filters, prefilter_files):
  """Executes the clang tool to extract annotations.
  Args:
    src_dir: str Path to the src directory of Chrome.
    build_dir: str Path to the build directory.
    path_filters: list of str List of paths to source directories for
        extraction.
    prefilter_files: bool Flag stating if source files should be first filtered
        using annotation related keywords and then given to clang tool.

  Returns:
    str Output of clang tool (extracted content and metadata of annotations).
  """
  args = [
        src_dir + "/tools/clang/scripts/run_tool.py",
        "--generate-compdb",
        "--tool=traffic_annotation_extractor",
        "-p=" + build_dir]
  if sys.platform == "win32":
      args.insert(0, "python")

  if prefilter_files:
    file_filter = TrafficAnnotationFileFilter(False)
    for path in path_filters:
      args += file_filter.GetFilteredFilesList(path)
  else:
    args += path_filters

  command = subprocess.Popen(args, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
  stdout_text, stderr_text = command.communicate()
  if stderr_text:
    print stderr_text
  return stdout_text


def _ParsRawAnnotations(raw_annotations):
  """Parses raw annotations texts which are received from the clang tool.
  Args:
    raw_annotations: str Serialization of annotations and metadata. Each
        annotation should have either of the following lines:
        1- "==== NEW ANNOTATION ===="
        2- File path.
        3- Name of the function including this position.
        4- Line number.
        5- Function Type.
        6- Unique id of annotation.
        7- Completing id or group id, when applicable, empty otherwise.
        8- Serialization of annotation text (several lines)
        n- "==== ANNOTATION ENDS ===="
        or:
        1: "==== NEW CALL ===="
        2: File path.
        3: Name of the function in which the call is made.
        4: Name of the called function.
        5: Does the call have an annotation?
        6: "==== CALL ENDS ===="

  Returns:
    annotations: ExtractedNetworkTrafficAnnotation A protobuf including all
      extracted annotations.
    metadata: list of dict List of metadata for each annotation. Each item
      includes the following fields:
        function_type: str Type of the function that defines the annotation.
        extra_id: str Possible prefix for annotation completion.
    errors: list of str List of errors.
  """
  annotations = traffic_annotation_pb2.ExtractedNetworkTrafficAnnotation()
  errors = []
  metadata = []

  lines = [line.strip("\r\n") for line in raw_annotations.split("\n")]
  current = 0

  try:
    while current < len(lines) - 1:
      if lines[current] == "==== NEW ANNOTATION ====":
        if current + 6 >= len(lines):
          raise Exception(
              "Not enough header lines at line %i." % current)

        # Extract header lines.
        source = traffic_annotation_pb2.NetworkTrafficAnnotation.TrafficSource()
        source.file = lines[current + 1]
        source.function = lines[current + 2]
        source.line = int(lines[current + 3])
        unique_id = lines[current + 5]

        new_metadata = {"function_type": lines[current + 4],
                        "extra_id": lines[current + 6],
                        "unique_id_hash": _ComputeStringHash(unique_id)}
        # Extract serialized proto.
        current += 7
        annotation_text = ""

        while current < len(lines):
          if lines[current] == "==== ANNOTATION ENDS ====":
            break
          else:
            annotation_text += lines[current]
          current += 1
        else:
          raise Exception(
            "Error at line %i, expected annotation end tag." % current)
        current += 1

        # Process unittests and undefined tags.
        if unique_id in ("test", "test_partial"):
          continue
        if unique_id in ("undefined", "missing"):
          errors.append("Annotation is not defined for file '%s', line %i." %
              (source.file, source.line))
          continue

        # Decode serialized proto.
        annotation_proto = traffic_annotation_pb2.NetworkTrafficAnnotation()
        try:
          text_format.Parse(annotation_text, annotation_proto)
        except Exception as error:
          errors.append("Annotation in file '%s', line %i, has an error: %s" %
              (source.file, source.line, error))

        # Add new proto.
        annotation_proto.unique_id = unique_id
        annotation_proto.source.CopyFrom(source)
        annotations.network_traffic_annotation.add().CopyFrom(annotation_proto)
        metadata.append(new_metadata)
      elif lines[current] == "==== NEW CALL ====":
        # Ignore calls for now.
        while current < len(lines):
          if lines[current] == "==== CALL ENDS ====":
            break
          current += 1
        else:
          raise Exception(
              "Error at line %i, expected call end tag." % current)
        current += 1
      else: # The line is neither new annotation nor new call.
        raise Exception(
            "Error at line %i, expected starting new annotation or call." %
            current)

  except Exception as error:
    errors.append(str(error))

  print "Extracted %i annotations with %i errors." % \
    (len(annotations.network_traffic_annotation), len(errors))
  return annotations, metadata, errors


def _WriteSummaryFile(annotations, metadata, errors, file_path):
  """Writes extracted annotations and errors into a simple text file.
  args:
    annotations: ExtractedNetworkTrafficAnnotation A protobuf including all
      extracted annotations.
    metadata: list of dict Metadata for annotations, as specified in the outputs
      of _ParsRawAnnotations function.
    errors: list of str List of all extraction errors.
    file_path: str File path to the brief summary file.
  """
  with open(file_path, "w") as summary_file:
    if errors:
      summary_file.write("Errors:\n%s\n\n" % "\n".join(errors))
    if len(annotations.network_traffic_annotation):
      summary_file.write("Annotations:\n")
      for annotation, meta in zip(annotations.network_traffic_annotation,
                                  metadata):
        summary_file.write(
            "%s\n+MetaData:%s\n---\n" % (str(annotation), str(meta)))


def _WriteHashCodesFile(annotations, metadata, file_path):
  """Writes unique ids and hash codes of annotations into a simple text file.
  args:
    annotations: ExtractedNetworkTrafficAnnotation A protobuf including all
      extracted annotations.
    metadata: list of dict Metadata for annotations, as specified in the outputs
      of _ParsRawAnnotations function.
    file_path: str File path to the brief summary file.
  """
  hash_list = []
  for annotation, meta in zip(annotations.network_traffic_annotation, metadata):
    hash_list += ["%s,%s" % (annotation.unique_id, meta["unique_id_hash"])]
  for keyword in ("test", "test_partial", "undefined", "missing"):
    hash_list += ["%s,%s" % (keyword, _ComputeStringHash(keyword))]
  open(file_path, "w").write("\n".join(sorted(hash_list)))


def main():
  parser = argparse.ArgumentParser(description="Traffic Annotation Auditor.")
  parser.add_argument("--build-dir",
                      help="Path to the build directory.")
  parser.add_argument("--extractor-output",
                      help="Optional path to the temporary file that extracted "
                           "annotations will be stored into.")
  parser.add_argument("--extractor-input",
                      help="Optional path to the file that temporary extracted "
                           "annotations are already stored in. If this is "
                           "provided, clang tool is not run and this is used "
                           "as input.")
  parser.add_argument("--summary-file",
                      help="Path to the output file with all annotations.")
  parser.add_argument("--hash-codes-file",
                      help="Path to the output file with the list of unique "
                           "ids and their hash codes.")
  parser.add_argument("path_filters",
                      nargs="*",
                      help="Optional paths to filter what files the tool is "
                           "run on.",
                      default=[""])
  parser.add_argument("--prefilter-files", action="store_true",
                      help="Checks source files for patterns of annotations "
                           "and network functions that may require annotation "
                           "and limits running clang tool only on them.")
  args = parser.parse_args()

  if not args.summary_file and not args.hash_codes_file:
    print "Warning: Output file not specified."

  # If a pre-extracted input file is provided, load it.
  if args.extractor_input:
    with open(args.extractor_input, "r") as raw_file:
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
        args.path_filters, args.prefilter_files)

  if args.extractor_output:
    with open(args.extractor_output, "w") as raw_file:
      raw_file.write(raw_annotations)

  annotations, metadata, errors = _ParsRawAnnotations(raw_annotations)

  if not annotations:
    print "Could not extract any annotation."
    if errors:
      print "Errors:\n%s" % "\n".join(errors)
    return 1

  if args.summary_file:
    _WriteSummaryFile(annotations, metadata, errors, args.summary_file)

  if args.hash_codes_file:
    _WriteHashCodesFile(annotations, metadata, args.hash_codes_file)

  return 0


if __name__ == "__main__":
  sys.exit(main())
