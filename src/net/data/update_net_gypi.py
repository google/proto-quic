# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import re
import StringIO
import sys


VARIABLE_PATTERN = re.compile("^(?P<indentation>\s*)'(?P<name>[^']*)':\s*\[$")
EXCLUSION_PATTERN = re.compile("^(?:README|OWNERS|.*\.(pyc?|sh|swp)|.*~)$")

DATA_SOURCES_PATH_FOR_VARIABLES = {
  "net_test_support_data_sources": [
    "net/data/ssl/certificates",
  ],
  "net_unittests_data_sources": [
    "net/data/cert_issuer_source_aia_unittest",
    "net/data/cert_issuer_source_static_unittest",
    "net/data/certificate_policies_unittest",
    "net/data/name_constraints_unittest",
    "net/data/parse_certificate_unittest",
    "net/data/parse_ocsp_unittest",
    "net/data/test.html",
    "net/data/url_request_unittest",
    "net/data/verify_certificate_chain_unittest",
    "net/data/verify_name_match_unittest/names",
    "net/data/verify_signed_data_unittest",
    "net/third_party/nist-pkits/certs",
    "net/third_party/nist-pkits/crls",
  ],
}


def list_data_sources(root, paths, exclusion):
  """Returns the list of data source found in |paths|.

  Args:
    root: string, path to the repository root
    paths: list of string, paths relative to repository root
    exclusion: compiled regular expression, filename matching this pattern
        will be excluded from the result
  """
  data_sources = []
  for path in paths:
    fullpath = os.path.normpath(os.path.join(root, path))
    if os.path.isfile(fullpath):
      if not exclusion.match(os.path.basename(path)):
        data_sources.append(path)
      continue

    for dirpath, dirnames, filenames in os.walk(fullpath):
      for filename in filenames:
        if not exclusion.match(filename):
          data_sources.append(os.path.normpath(os.path.join(dirpath, filename)))
  return data_sources


def format_data_sources(name, dir, data_sources, indentation):
  """Converts |data_sources| to a gyp variable assignment.

  Args:
    name: string, name of the variable
    dir: string, path to the directory containing the gyp file
    data_sources: list of filenames
    indentation: string
  """
  buffer = StringIO.StringIO()
  buffer.write("%s'%s': [\n" % (indentation, name))
  for data_source in sorted(data_sources):
    buffer.write("  %s'%s',\n" % (
        indentation, os.path.relpath(data_source, dir)))
  buffer.write("%s],\n" % (indentation,))
  return buffer.getvalue()


def save_file_if_changed(path, content):
  """Writes |content| to file at |path| if file has changed.

  Args:
    path: string, path of the file to save
    content: string, content to write to file
  """
  with open(path, "r") as file:
    old_content = file.read()
  if content != old_content:
    with open(path, "w") as file:
      file.write(content)
    sys.stdout.write("updated %s, do not forget to run 'git add'\n" % (path,))


def edit_file(path, root, data_sources_for_variables):
  """Updates file at |path| by rewriting variables values.

  Args:
    path: string, path of the file to edit
    root: string, path to the repository root
    data_sources_for_variables: dictionary mapping variable names to
        the list of data sources to use
  """
  dir = os.path.relpath(os.path.dirname(path), root)
  buffer = StringIO.StringIO()
  with open(path, "r") as file:
    indentation = ""
    current_var = None
    for line in file:
      if not current_var:
        match = VARIABLE_PATTERN.match(line)
        if not match:
          buffer.write(line)
          continue
        variable = match.group("name")
        if variable not in data_sources_for_variables:
          buffer.write(line)
          continue
        current_var = variable
        indentation = match.group("indentation")
        buffer.write(format_data_sources(
            variable, dir, data_sources_for_variables[variable], indentation))
      else:
        if line == indentation + "],\n":
          current_var = None
  save_file_if_changed(path, buffer.getvalue())


def main(args):
  root_dir = os.path.normpath(os.path.join(
      os.path.dirname(__file__), os.pardir, os.pardir))
  net_gypi = os.path.normpath(os.path.join(root_dir, "net", "net.gypi"))

  data_sources_for_variables = {}
  for variable in DATA_SOURCES_PATH_FOR_VARIABLES:
    data_sources_for_variables[variable] = list_data_sources(
        root_dir, DATA_SOURCES_PATH_FOR_VARIABLES[variable], EXCLUSION_PATTERN)

  edit_file(net_gypi, root_dir, data_sources_for_variables)


if __name__ == "__main__":
  sys.exit(main(sys.argv[1:]))
