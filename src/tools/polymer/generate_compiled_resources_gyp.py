#!/usr/bin/env python
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from bs4 import BeautifulSoup
from datetime import date
import os.path as path
import sys


_SRC = path.join(path.dirname(path.abspath(__file__)), "..", "..")
_COMPILE_JS = path.join(
    _SRC, "third_party", "closure_compiler", "compile_js2.gypi")
_POLYMERS = ["polymer%s.html" % p for p in "", "-mini", "-micro"]
_WEB_ANIMATIONS_BASE = "web-animations.html"
_WEB_ANIMATIONS_TARGET = "<(EXTERNS_GYP):web_animations"
_COMPILED_RESOURCES_TEMPLATE = """
# Copyright %d The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# NOTE: Created with %s, please do not edit.
{
  'targets': [
    %s
  ],
}
""".strip()


def main(created_by, html_files):
  targets = ""

  def _target_name(target_file):
    assert target_file.endswith(".html")
    return path.basename(target_file)[:-len(".html")] + "-extracted"

  for html_file in sorted(html_files, key=_target_name):
    html_base = path.basename(html_file)
    if html_base in _POLYMERS:
      continue

    parsed = BeautifulSoup(open(html_file), "html.parser")
    imports = set(i.get("href") for i in parsed.find_all("link", rel="import"))

    html_dir = path.dirname(html_file)
    dependencies = []

    for html_import in sorted(imports):
      import_dir, import_base = path.split(html_import.encode("ascii"))
      if import_base in _POLYMERS:
        continue

      if import_base == _WEB_ANIMATIONS_BASE:
        dependencies.append(_WEB_ANIMATIONS_TARGET)
        continue

      target = _target_name(import_base)
      if not path.isfile(path.join(html_dir, import_dir, target + ".js")):
        continue

      if import_dir:
        target = "compiled_resources2.gyp:" + target

      dependencies.append(path.join(import_dir, target))

    path_to_compile_js = path.relpath(_COMPILE_JS, html_dir)

    targets += "\n    {"
    targets += "\n      'target_name': '%s-extracted'," % html_base[:-5]
    if dependencies:
      targets += "\n      'dependencies': ["
      targets += "\n        '%s'," % "',\n        '".join(dependencies)
      targets += "\n      ],"
    targets += "\n      'includes': ['%s']," % path_to_compile_js
    targets += "\n    },"

  targets = targets.strip()

  if targets:
    current_year = date.today().year
    print _COMPILED_RESOURCES_TEMPLATE % (current_year, created_by, targets)


if __name__ == "__main__":
  main(path.basename(sys.argv[0]), sys.argv[1:])
