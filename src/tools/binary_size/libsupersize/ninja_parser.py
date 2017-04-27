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


class _SourceMapper(object):
  def __init__(self, dep_map, parsed_file_count):
    self._dep_map = dep_map
    self.parsed_file_count = parsed_file_count
    self._unmatched_paths = set()

  def _FindSourceForPathInternal(self, path):
    if not path.endswith(')'):
      return self._dep_map.get(path)

    # foo/bar.a(baz.o)
    start_idx = path.index('(')
    lib_name = path[:start_idx]
    obj_name = path[start_idx + 1:-1]
    by_basename = self._dep_map.get(lib_name)
    if not by_basename:
      return None
    obj_path = by_basename.get(obj_name)
    if not obj_path:
      # Found the library, but it doesn't list the .o file.
      logging.warning('no obj basename for %s', path)
      return None
    return self._dep_map.get(obj_path)

  def FindSourceForPath(self, path):
    """Returns the source path for the given object path (or None if not found).

    Paths for objects within archives should be in the format: foo/bar.a(baz.o)
    """
    ret = self._FindSourceForPathInternal(path)
    if not ret and path not in self._unmatched_paths:
      if self.unmatched_paths_count < 10:
        logging.warning('Could not find source path for %s', path)
      self._unmatched_paths.add(path)
    return ret

  @property
  def unmatched_paths_count(self):
    return len(self._unmatched_paths)


def _ParseOneFile(lines, dep_map):
  sub_ninjas = []
  for line in lines:
    if line.startswith('subninja '):
      sub_ninjas.append(line[9:-1])
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
  return sub_ninjas


def Parse(output_directory):
  to_parse = ['build.ninja']
  seen_paths = set(to_parse)
  dep_map = {}
  while to_parse:
    path = os.path.join(output_directory, to_parse.pop())
    with open(path) as obj:
      sub_ninjas = _ParseOneFile(obj, dep_map)
    for subpath in sub_ninjas:
      assert subpath not in seen_paths, 'Double include of ' + subpath
      seen_paths.add(subpath)
    to_parse.extend(sub_ninjas)

  return _SourceMapper(dep_map, len(seen_paths))
