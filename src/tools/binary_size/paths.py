# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Functions for dealing with determining --tool-prefix."""

import distutils.spawn
import logging
import os

_STATUS_DETECTED = 1
_STATUS_VERIFIED = 2


def AddOptions(parser):
  parser.add_argument('--tool-prefix', default='',
                      help='Path prefix for c++filt.')
  parser.add_argument('--output-directory',
                      help='Path to the root build directory.')


class LazyPaths(object):
  def __init__(self, args=None, tool_prefix=None, output_directory=None,
               input_file=None):
    tool_prefix = tool_prefix or (args and args.tool_prefix)
    output_directory = output_directory or (args and args.output_directory)
    self._tool_prefix = tool_prefix
    self._output_directory = output_directory
    self._input_file = input_file
    self._output_directory_status = _STATUS_DETECTED if output_directory else 0
    self._tool_prefix_status = _STATUS_DETECTED if tool_prefix else 0

  @property
  def tool_prefix(self):
    if self._tool_prefix_status < _STATUS_DETECTED:
      self._tool_prefix_status = _STATUS_DETECTED
      self._tool_prefix = self._DetectToolPrefix() or ''
      logging.debug('Detected --tool-prefix=%s', self._tool_prefix)
    return self._tool_prefix

  @property
  def output_directory(self):
    if self._output_directory_status < _STATUS_DETECTED:
      self._output_directory_status = _STATUS_DETECTED
      self._output_directory = self._DetectOutputDirectory()
      logging.debug('Detected --output-directory=%s', self._output_directory)
    return self._output_directory

  def VerifyOutputDirectory(self):
    output_directory = self.output_directory
    if self._output_directory_status < _STATUS_VERIFIED:
      self._output_directory_status = _STATUS_VERIFIED
      if not output_directory or not os.path.isdir(output_directory):
        raise Exception('Bad --output-directory. Path not found: %s' %
                        output_directory)
      logging.info('Using --output-directory=%s', output_directory)
    return output_directory

  def VerifyToolPrefix(self):
    tool_prefix = self.tool_prefix
    if self._tool_prefix_status < _STATUS_VERIFIED:
      self._tool_prefix_status = _STATUS_VERIFIED
      if os.path.sep not in tool_prefix:
        full_path = distutils.spawn.find_executable(tool_prefix + 'c++filt')
      else:
        full_path = tool_prefix + 'c++filt'

      if not full_path or not os.path.isfile(full_path):
        raise Exception('Bad --tool-prefix. Path not found: %s' % full_path)
      logging.info('Using --tool-prefix=%s', self._tool_prefix)
    return tool_prefix

  def _DetectOutputDirectory(self):
    # See if input file is in out/Release.
    abs_path = os.path.abspath(self._input_file)
    release_idx = abs_path.find('Release')
    if release_idx != -1:
      output_directory = abs_path[:release_idx] + 'Release'
      output_directory = os.path.relpath(abs_path[:release_idx] + '/Release')
      return output_directory

    # See if CWD=output directory.
    if os.path.exists('build.ninja'):
      return '.'
    return None

  def _DetectToolPrefix(self):
    output_directory = self.output_directory
    if output_directory:
      # Auto-detect from build_vars.txt
      build_vars_path = os.path.join(output_directory, 'build_vars.txt')
      if os.path.exists(build_vars_path):
        with open(build_vars_path) as f:
          build_vars = dict(l.rstrip().split('=', 1) for l in f if '=' in l)
        return os.path.normpath(
            os.path.join(output_directory, build_vars['android_tool_prefix']))
    return None
