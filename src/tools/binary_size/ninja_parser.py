# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Extract source file information from .ninja files."""

import logging
import os
import re


# E.g.:
# build obj/.../foo.o: cxx gen/.../foo.cc || obj/.../foo.inputdeps.stamp
# build obj/.../libfoo.a: alink obj/.../a.o obj/.../b.o |
_REGEX = re.compile(r'build ([^:]+?\.[ao]): \w+ (.*?)(?: \||\n|$)')


class SourceFileMapper(object):
  def __init__(self, output_directory):
    self._output_directory = output_directory
    self._ninja_files_to_parse = ['build.ninja']
    self._seen_ninja_files = set(('build.ninja',))
    self._dep_map = {}

  def _ParseNinja(self, path):
    with open(os.path.join(self._output_directory, path)) as obj:
      self._ParseNinjaLines(obj)

  def _ParseNinjaLines(self, lines):
    dep_map = self._dep_map
    sub_ninjas = []
    for line in lines:
      if line.startswith('subninja '):
        subpath = line[9:-1]
        assert subpath not in self._seen_ninja_files, (
            'Double include of ' + subpath)
        self._seen_ninja_files.add(subpath)
        sub_ninjas.append(subpath)
        continue
      m = _REGEX.match(line)
      if m:
        output, srcs = m.groups()
        output = output.replace('\\ ', ' ')
        assert output not in dep_map, 'Duplicate output: ' + output
        if output[-1] == 'o':
          dep_map[output] = srcs.replace('\\ ', ' ')
        else:
          srcs = srcs.replace('\\ ', '\b')
          obj_paths = (s.replace('\b', ' ') for s in srcs.split(' '))
          dep_map[output] = {os.path.basename(p): p for p in obj_paths}

    # Add reversed so that the first on encoundered is at the top of the stack.
    self._ninja_files_to_parse.extend(reversed(sub_ninjas))

  def _Lookup(self, path):
    """Looks for |path| within self._dep_map.

    If not found, continues to parse subninjas until it is found or there are no
    more subninjas.
    """
    ret = self._dep_map.get(path)
    while not ret and self._ninja_files_to_parse:
      self._ParseNinja(self._ninja_files_to_parse.pop())
      ret = self._dep_map.get(path)
    return ret

  def FindSourceForPath(self, path):
    """Returns the source path for the given object path (or None if not found).

    Paths for objects within archives should be in the format: foo/bar.a(baz.o)
    """
    if not path.endswith(')'):
      return self._Lookup(path)

    # foo/bar.a(baz.o)
    start_idx = path.index('(')
    lib_name = path[:start_idx]
    obj_name = path[start_idx + 1:-1]
    by_basename = self._Lookup(lib_name)
    if not by_basename:
      return None
    obj_path = by_basename.get(obj_name)
    if not obj_path:
      # Found the library, but it doesn't list the .o file.
      logging.warning('no obj basename for %s', path)
      return None
    return self._Lookup(obj_path)

  def GetParsedFileCount(self):
    return len(self._seen_ninja_files)
