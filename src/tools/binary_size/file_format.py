# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Deals with loading & saving .size files."""

import ast
import gzip
import models


# File format version for .size files.
_SERIALIZATION_VERSION = 1


def EndsWithMaybeGz(path, suffix):
  return path.endswith(suffix) or path.endswith(suffix + '.gz')


def OpenMaybeGz(path, mode=None):
  """Calls `gzip.open()` if |path| ends in ".gz", otherwise calls `open()`."""
  if path.endswith('.gz'):
    if mode and 'w' in mode:
      return gzip.GzipFile(path, mode, 1)
    return gzip.open(path, mode)
  return open(path, mode or 'r')


def _SaveSizeInfoToFile(result, file_obj):
  """Saves the result to the given file object."""
  # Store one bucket per line.
  file_obj.write('%d\n' % _SERIALIZATION_VERSION)
  file_obj.write('%r\n' % result.section_sizes)
  file_obj.write('%d\n' % len(result.symbols))
  prev_section_name = None
  # Store symbol fields as tab-separated.
  # Store only non-derived fields.
  for symbol in result.symbols:
    if symbol.section_name != prev_section_name:
      file_obj.write('%s\n' % symbol.section_name)
      prev_section_name = symbol.section_name
    # Don't write padding nor name since these are derived values.
    file_obj.write('%x\t%x\t%s\t%s\n' % (
        symbol.address, symbol.size_without_padding,
        symbol.function_signature or symbol.name, symbol.path))


def _LoadSizeInfoFromFile(file_obj):
  """Loads a result from the given file."""
  lines = iter(file_obj)
  actual_version = int(next(lines))
  assert actual_version == _SERIALIZATION_VERSION, (
      'Version mismatch. Need to write some upgrade code.')

  section_sizes = ast.literal_eval(next(lines))
  num_syms = int(next(lines))
  symbol_list = [None] * num_syms
  section_name = None
  for i in xrange(num_syms):
    line = next(lines)[:-1]
    if '\t' not in line:
      section_name = line
      line = next(lines)[:-1]
    new_sym = models.Symbol.__new__(models.Symbol)
    parts = line.split('\t')
    new_sym.section_name = section_name
    new_sym.address = int(parts[0], 16)
    new_sym.size = int(parts[1], 16)
    new_sym.name = parts[2]
    new_sym.path = parts[3]
    new_sym.padding = 0  # Derived
    new_sym.function_signature = None  # Derived
    symbol_list[i] = new_sym

  return models.SizeInfo(models.SymbolGroup(symbol_list), section_sizes)


def SaveSizeInfo(result, path):
  with OpenMaybeGz(path, 'wb') as f:
    _SaveSizeInfoToFile(result, f)


def LoadSizeInfo(path):
  with OpenMaybeGz(path) as f:
    return _LoadSizeInfoFromFile(f)
