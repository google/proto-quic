# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Unit tests for the source_control module."""

import unittest
import mock

import source_control


class SourceControlTest(unittest.TestCase):

  @mock.patch('source_control.bisect_utils.CheckRunGit')
  def testQueryRevisionInfo(self, mock_run_git):
    # The QueryRevisionInfo function should run a sequence of git commands,
    # then returns a dict with the results.
    command_output_map = [
        (['log', '--format=%aN', '-1', 'abcd1234'], 'Some Name\n'),
        (['log', '--format=%aE', '-1', 'abcd1234'], 'somename@x.com'),
        (['log', '--format=%s', '-1', 'abcd1234'], 'Commit subject '),
        (['log', '--format=%cD', '-1', 'abcd1234'], 'Fri, 10 Oct 2014'),
        (['log', '--format=%b', '-1', 'abcd1234'], 'Commit body\n'),
    ]
    _SetMockCheckRunGitBehavior(mock_run_git, command_output_map)
    # The result of calling QueryRevisionInfo is a dictionary like that below.
    # Trailing whitespace is stripped.
    expected = {
        'author': 'Some Name',
        'email': 'somename@x.com',
        'date': 'Fri, 10 Oct 2014',
        'subject': 'Commit subject',
        'body': 'Commit body',
    }
    self.assertEqual(expected, source_control.QueryRevisionInfo('abcd1234'))
    self.assertEqual(5, mock_run_git.call_count)

  def testResolveToRevision_InputGitHash(self):
    # The ResolveToRevision function returns a git commit hash corresponding
    # to the input, so if the input can't be parsed as an int, it is returned.
    self.assertEqual(
        'abcd1234',
        source_control.ResolveToRevision('abcd1234', 'chromium', {}, 5))

    # Note: It actually does this for any junk that isn't an int. This isn't
    # necessarily desired behavior.
    self.assertEqual(
        'foo bar',
        source_control.ResolveToRevision('foo bar', 'chromium', {}, 5))

  @mock.patch('source_control.bisect_utils.CheckRunGit')
  def testResolveToRevision_NotFound(self, mock_run_git):
    # If no corresponding git hash was found, then None is returned.
    mock_run_git.return_value = ''
    self.assertIsNone(
        source_control.ResolveToRevision('12345', 'chromium', {}, 5))

  @mock.patch('source_control.bisect_utils.CheckRunGit')
  def testResolveToRevision_Found(self, mock_run_git):
    # In general, ResolveToRevision finds a git commit hash by repeatedly
    # calling "git log --grep ..." with different numbers until something
    # matches.
    mock_run_git.return_value = 'abcd1234'
    self.assertEqual(
        'abcd1234',
        source_control.ResolveToRevision('12345', 'chromium', {}, 5))
    self.assertEqual(1, mock_run_git.call_count)


def _SetMockCheckRunGitBehavior(mock_obj, command_output_map):
  """Sets the behavior of a mock function according to the given mapping."""
  # Unused argument 'cwd', expected in args list but not needed.
  # pylint: disable=W0613
  def FakeCheckRunGit(in_command, cwd=None):
    for command, output in command_output_map:
      if command == in_command:
        return output
  mock_obj.side_effect = FakeCheckRunGit


if __name__ == '__main__':
  unittest.main()
