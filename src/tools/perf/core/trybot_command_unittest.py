# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
import argparse
import base64
import io
import gzip
import json
import logging
import os
import StringIO
import sys
import tempfile
import unittest

from core import trybot_command
import mock
from telemetry import benchmark


class FakeProcess(object):

  def __init__(self, expected_responses):
    self._communicate = expected_responses[1:]
    self._poll = expected_responses[0]

  def communicate(self):
    return self._communicate

  def poll(self):
    return self._poll


class TrybotCommandTest(unittest.TestCase):

  # pylint: disable=protected-access

  def setUp(self):
    self.log_output = StringIO.StringIO()
    self.stream_handler = logging.StreamHandler(self.log_output)
    logging.getLogger().addHandler(self.stream_handler)
    self._subprocess_patcher = mock.patch('core.trybot_command.subprocess')
    self._mock_subprocess = self._subprocess_patcher.start()
    self._urllib2_patcher = mock.patch('core.trybot_command.urllib2')
    self._urllib2_mock = self._urllib2_patcher.start()
    self._tempfile_patcher =  mock.patch('core.trybot_command.tempfile')
    self._tempfile_mock = self._tempfile_patcher.start()
    # Always set git command to 'git' to simplify testing across platforms.
    self._original_git_cmd = trybot_command._GIT_CMD
    trybot_command._GIT_CMD = 'git'

  def tearDown(self):
    logging.getLogger().removeHandler(self.stream_handler)
    self.log_output.close()
    self._subprocess_patcher.stop()
    self._urllib2_patcher.stop()
    self._tempfile_patcher.stop()
    # Reset the cached builders in trybot_command
    trybot_command.Trybot._builders = None
    trybot_command._GIT_CMD = self._original_git_cmd

  def _ExpectProcesses(self, expected_args_list):
    counter = [-1]
    def side_effect(args, **kwargs):
      if not expected_args_list:
        self.fail(
            'Not expect any Popen() call but got a Popen call with %s\n' % args)
      del kwargs  # unused
      counter[0] += 1
      expected_args, expected_responses = expected_args_list[counter[0]]
      self.assertEquals(
          expected_args, args,
          'Popen() is called with unexpected args.\n Actual: %s.\n'
          'Expecting (index %i): %s' % (args, counter[0], expected_args))
      return FakeProcess(expected_responses)
    self._mock_subprocess.Popen.side_effect = side_effect

  def _MockBuilderList(self):
    excluded_bots = trybot_command.EXCLUDED_BOTS
    builders = [bot for bot in self._builder_list if bot not in excluded_bots]
    return builders

  def _MockTryserverJson(self, bots_dict):
    data_to_compress = json.dumps({'builders': bots_dict})

    with io.BytesIO() as dst:
      with gzip.GzipFile(fileobj=dst, mode='wb') as src:
        src.write(data_to_compress)
      compressed_data = dst.getvalue()

    milo_data = {'data': base64.b64encode(compressed_data)}
    milo_data = json.dumps(milo_data)
    milo_data = trybot_command._MILO_RESPONSE_PREFIX + milo_data

    data = mock.Mock()
    data.read.return_value = milo_data
    self._urllib2_mock.urlopen.return_value = data

  def _MockTempFile(self, issue, issue_url):
    fd, temp_file = tempfile.mkstemp(suffix='.json', prefix='cl')
    with open(temp_file, 'w') as f:
      json.dump({"issue": issue, "issue_url": issue_url}, f)
    self._tempfile_mock.mkstemp.return_value = (fd, temp_file)
    return temp_file

  def _AssertTryBotExceptions(self, message, func, *args):
    with self.assertRaises(trybot_command.TrybotError) as e:
      func(*args)
    self.assertIn(message, e.exception.message)

  def _SetupTrybotCommand(
      self, try_json_dict, trybot, benchmark_name='sunspider',
      repo_path=trybot_command.CHROMIUM_SRC_PATH, deps_revision=None):
    self._MockTryserverJson(try_json_dict)
    command = trybot_command.Trybot()
    command._InitializeBuilderNames(trybot)
    opts = argparse.Namespace(
        trybot=trybot, benchmark_name=benchmark_name, repo_path=repo_path,
        deps_revision=deps_revision)

    return command, opts

  def _GetConfigForTrybot(self, name, platform, extra_benchmark_args=None,
                          repo_path=trybot_command.CHROMIUM_SRC_PATH,
                          deps_revision=None):
    bot = '%s_perf_bisect' % name.replace('', '').replace('-', '_')
    command, options = self._SetupTrybotCommand(
        {bot: 'stuff'}, name, repo_path=repo_path, deps_revision=deps_revision)
    extra_benchmark_args = extra_benchmark_args or []
    arguments = [options.benchmark_name] + extra_benchmark_args
    cfg = command._GetPerfConfig(platform, arguments)

    return cfg, command

  def _ExpectedGitTryTestArgs(self, test_name, browser, target_arch='ia32'):
    return ('perf_try_config={'
            '"repeat_count": "1", "command": "src/tools/perf/run_benchmark '
            '--browser=%s %s --verbose", "max_time_minutes": "120", '
            '"target_arch": "%s", "truncate_percent": "0"}' % (
                browser, test_name, target_arch))

  def testFindAllBrowserTypesList(self):
    self._MockTryserverJson({
        'android_nexus4_perf_bisect': 'stuff',
        'mac_10_9_perf_bisect': 'otherstuff',
        'win_perf_bisect_builder': 'not a trybot',
    })
    expected_trybots_list = [
        'all',
        'all-android',
        'all-linux',
        'all-mac',
        'all-win',
        'android-nexus4',
        'mac-10-9'
    ]
    parser = trybot_command.Trybot.CreateParser()
    trybot_command.Trybot.AddCommandLineArgs(parser, None)
    trybot_action = [a for a in parser._actions if a.dest == 'trybot'][0]
    self.assertEquals(
        expected_trybots_list,
        sorted(trybot_action.choices))

  def testFindAllBrowserTypesTrybot(self):
    self._MockTryserverJson({
        'android_nexus4_perf_bisect': 'stuff',
        'mac_10_9_perf_bisect': 'otherstuff',
        'win_perf_bisect_builder': 'not a trybot',
    })
    expected_trybots_list = [
        'all',
        'all-android',
        'all-linux',
        'all-mac',
        'all-win',
        'android-nexus4',
        'mac-10-9'
    ]

    parser = trybot_command.Trybot.CreateParser()
    trybot_command.Trybot.AddCommandLineArgs(parser, None)
    trybot_action = [a for a in parser._actions if a.dest == 'trybot'][0]
    self.assertEquals(expected_trybots_list, sorted(trybot_action.choices))

  def testFindAllBrowserTypesNonTrybotBrowser(self):
    self._MockTryserverJson({})
    parser = trybot_command.Trybot.CreateParser()
    trybot_command.Trybot.AddCommandLineArgs(parser, None)
    trybot_action = [a for a in parser._actions if a.dest == 'trybot'][0]
    self.assertEquals(
        ['all', 'all-android', 'all-linux', 'all-mac', 'all-win'],
        sorted(trybot_action.choices))

  def testConstructor(self):
    self._MockTryserverJson({
        'android_nexus4_perf_bisect': 'stuff',
        'mac_10_9_perf_bisect': 'otherstuff',
        'win_perf_bisect_builder': 'not a trybot',
    })
    command = trybot_command.Trybot()
    command._InitializeBuilderNames('android-nexus4')
    self.assertTrue('android' in command._builder_names)
    self.assertEquals(['android_nexus4_perf_bisect'],
                      command._builder_names.get('android'))

  def testConstructorTrybotAll(self):
    self._MockTryserverJson({
        'android_nexus4_perf_bisect': 'stuff',
        'android_nexus5_perf_bisect': 'stuff2',
        'mac_10_9_perf_bisect': 'otherstuff',
        'mac_perf_bisect': 'otherstuff1',
        'win_perf_bisect': 'otherstuff2',
        'linux_perf_bisect': 'otherstuff3',
        'win_x64_perf_bisect': 'otherstuff4',
        'win_perf_bisect_builder': 'not a trybot',
    })
    command = trybot_command.Trybot()
    command._InitializeBuilderNames('all')
    self.assertEquals(
        ['android', 'linux', 'mac', 'win', 'win-x64'],
        sorted(command._builder_names))
    self.assertEquals(
        ['android_nexus4_perf_bisect', 'android_nexus5_perf_bisect'],
        sorted(command._builder_names.get('android')))
    self.assertEquals(
        ['mac_10_9_perf_bisect', 'mac_perf_bisect'],
        sorted(command._builder_names.get('mac')))
    self.assertEquals(
        ['linux_perf_bisect'], sorted(command._builder_names.get('linux')))
    self.assertEquals(
        ['win_perf_bisect'], sorted(command._builder_names.get('win')))
    self.assertEquals(
        ['win_x64_perf_bisect'], sorted(command._builder_names.get('win-x64')))

  def testConstructorTrybotAllWin(self):
    self._MockTryserverJson({
        'android_nexus4_perf_bisect': 'stuff',
        'android_nexus5_perf_bisect': 'stuff2',
        'win_8_perf_bisect': 'otherstuff',
        'win_perf_bisect': 'otherstuff2',
        'linux_perf_bisect': 'otherstuff3',
        'win_x64_perf_bisect': 'otherstuff4',
        'win_perf_bisect_builder': 'not a trybot',
        'win_x64_10_perf_bisect': 'otherstuff4',
        'winx64ati_perf_bisect': 'not a trybot',
        'winx64nvidia_perf_bisect': 'not a trybot',
    })
    command = trybot_command.Trybot()
    command._InitializeBuilderNames('all-win')
    self.assertEquals(
        ['win', 'win-x64'],
        sorted(command._builder_names))
    self.assertEquals(
        ['win_8_perf_bisect', 'win_perf_bisect'],
        sorted(command._builder_names.get('win')))
    self.assertNotIn(
        'win_x64_perf_bisect',
        sorted(command._builder_names.get('win')))
    self.assertEquals(
        sorted(['win_x64_perf_bisect', 'win_x64_10_perf_bisect',
                'winx64ati_perf_bisect', 'winx64nvidia_perf_bisect']),
        sorted(command._builder_names.get('win-x64')))

  def testConstructorTrybotAllAndroid(self):
    self._MockTryserverJson({
        'android_nexus4_perf_bisect': 'stuff',
        'android_nexus5_perf_bisect': 'stuff2',
        'win_8_perf_bisect': 'otherstuff',
        'win_perf_bisect': 'otherstuff2',
        'linux_perf_bisect': 'otherstuff3',
        'win_x64_perf_bisect': 'otherstuff4',
        'win_perf_bisect_builder': 'not a trybot',
    })
    command = trybot_command.Trybot()
    command._InitializeBuilderNames('all-android')
    self.assertEquals(
        ['android_nexus4_perf_bisect', 'android_nexus5_perf_bisect'],
        sorted(command._builder_names.get('android')))

  def testConstructorTrybotAllMac(self):
    self._MockTryserverJson({
        'android_nexus4_perf_bisect': 'stuff',
        'win_8_perf_bisect': 'otherstuff',
        'mac_perf_bisect': 'otherstuff2',
        'win_perf_bisect_builder': 'not a trybot',
    })
    command = trybot_command.Trybot()
    command._InitializeBuilderNames('all-mac')
    self.assertEquals(
        ['mac'],
        sorted(command._builder_names))
    self.assertEquals(
        ['mac_perf_bisect'],
        sorted(command._builder_names.get('mac')))

  def testConstructorTrybotAllLinux(self):
    self._MockTryserverJson({
        'android_nexus4_perf_bisect': 'stuff',
        'linux_perf_bisect': 'stuff1',
        'win_8_perf_bisect': 'otherstuff',
        'mac_perf_bisect': 'otherstuff2',
        'win_perf_bisect_builder': 'not a trybot',
    })
    command = trybot_command.Trybot()
    command._InitializeBuilderNames('all-linux')
    self.assertEquals(
        ['linux'],
        sorted(command._builder_names))
    self.assertEquals(
        ['linux_perf_bisect'],
        sorted(command._builder_names.get('linux')))

  @mock.patch('core.trybot_command.os.path.abspath',
              mock.MagicMock(return_value='/dummy/path'))
  @mock.patch('core.trybot_command.os.path.exists',
              mock.MagicMock(return_value=False))
  def testRepoPathExists(self):
    command, options = self._SetupTrybotCommand(
        {'linux_perf_bisect': 'stuff'}, 'linux', repo_path='/dummy/path')
    command.Run(options)
    self.assertEquals((
        '(ERROR) Perf Try Job: Repository path "/dummy/path" does not exist, '
        'please check the value of <repo_path> argument.'),
                      sys.stdout.getvalue().strip())

  def testNoGit(self):
    command, options = self._SetupTrybotCommand({'linux_perf_bisect': 'stuff'},
                                                'linux')
    self._ExpectProcesses((
        (['git', 'rev-parse', '--abbrev-ref', '--show-toplevel', 'HEAD'],
         (128, None, None)),
    ))
    self._AssertTryBotExceptions(
        ('%s is not a git repository, must be in a git repository to send '
         'changes to trybots.' % os.getcwd()),
        command._GetRepoAndBranchName,
        options.repo_path
    )

  def testDettachedBranch(self):
    command, options = self._SetupTrybotCommand({'linux_perf_bisect': 'stuff'},
                                                'linux')
    self._ExpectProcesses((
        (['git', 'rev-parse', '--abbrev-ref', '--show-toplevel', 'HEAD'],
         (0, '/root/path_to/repo/src\nHEAD\n', None)),
    ))
    self._AssertTryBotExceptions(
        'Not on a valid branch, looks like branch is dettached. [branch:HEAD]',
        command._GetRepoAndBranchName,
        options.repo_path
    )

  def testDirtyTree(self):
    command, options = self._SetupTrybotCommand({'linux_perf_bisect': 'stuff'},
                                                'linux')
    self._ExpectProcesses((
        (['git', 'rev-parse', '--abbrev-ref', '--show-toplevel', 'HEAD'],
         (0, '/root/path_to/repo/src\nbr\n', None)),
        (['git', 'update-index', '--refresh', '-q'], (0, '', None,)),
        (['git', 'diff-index', 'HEAD'], (0, 'dirty tree', None)),
    ))
    self._AssertTryBotExceptions(
        'Cannot send a try job with a dirty tree.',
        command._GetRepoAndBranchName,
        options.repo_path
    )

  def testGetRepoAndBranchName(self):
    command, options = self._SetupTrybotCommand({'linux_perf_bisect': 'stuff'},
                                                'linux')
    self._ExpectProcesses((
        (['git', 'rev-parse', '--abbrev-ref', '--show-toplevel', 'HEAD'],
         (0, '/root/path_to/repo/src\nbr\n', None)),
        (['git', 'update-index', '--refresh', '-q'], (0, '', None,)),
        (['git', 'diff-index', 'HEAD'], (0, '', None)),
    ))
    self.assertEquals(
        command._GetRepoAndBranchName(options.repo_path), ('src', 'br'))

  def testErrorOnBrowserArgSpecified(self):
    parser = trybot_command.Trybot.CreateParser()
    options, extra_args = parser.parse_known_args(
        ['sunspider', '--trybot=android-all', '--browser=mac'])
    with self.assertRaises(SystemExit):
      trybot_command.Trybot.ProcessCommandLineArgs(
          parser, options, extra_args, None)

  def testConfigAndroid(self):
    config, _ = self._GetConfigForTrybot('android-nexus4', 'android')
    self.assertEquals(
        {'command': ('src/tools/perf/run_benchmark '
                     '--browser=android-chromium sunspider --verbose'),
         'max_time_minutes': '120',
         'repeat_count': '1',
         'target_arch': 'ia32',
         'truncate_percent': '0'
        }, config)

  def testConfigMac(self):
    config, _ = self._GetConfigForTrybot('mac-10-9', 'mac')
    self.assertEquals(
        {'command': ('src/tools/perf/run_benchmark '
                     '--browser=release sunspider --verbose'),
         'max_time_minutes': '120',
         'repeat_count': '1',
         'target_arch': 'ia32',
         'truncate_percent': '0'
        }, config)

  def testConfigWinX64(self):
    config, _ = self._GetConfigForTrybot('win-x64', 'win-x64')

    self.assertEquals(
        {'command': ('src/tools/perf/run_benchmark '
                     '--browser=release_x64 sunspider --verbose'),
         'max_time_minutes': '120',
         'repeat_count': '1',
         'target_arch': 'x64',
         'truncate_percent': '0'
        }, config)

  def testVerboseOptionIsNotAddedTwice(self):
    config, _ = self._GetConfigForTrybot(
        'win-x64', 'win-x64', extra_benchmark_args=['-v'])
    self.assertEquals(
        {'command': ('src/tools/perf/run_benchmark '
                     '--browser=release_x64 sunspider -v'),
         'max_time_minutes': '120',
         'repeat_count': '1',
         'target_arch': 'x64',
         'truncate_percent': '0'
        }, config)

  def testConfigWinX64WithNoHyphen(self):
    config, _ = self._GetConfigForTrybot('winx64nvidia', 'win-x64')
    self.assertEquals(
        {'command': ('src/tools/perf/run_benchmark '
                     '--browser=release_x64 sunspider --verbose'),
         'max_time_minutes': '120',
         'repeat_count': '1',
         'target_arch': 'x64',
         'truncate_percent': '0'
        }, config)

  def testUnsupportedTrybot(self):
    self.assertRaises(
        trybot_command.TrybotError,
        trybot_command._GetBuilderNames,
        'arms-nvidia',
        {'win_perf_bisect': 'stuff'}
    )

  def testGetChangeListCommandError(self):
    temp_file = self._MockTempFile(None, None)
    command, _ = self._SetupTrybotCommand(
        {'linux_perf_bisect': 'stuff'}, 'linux')
    self._ExpectProcesses((
        (['git', 'cl', 'issue', '--json', temp_file], (128, None, None)),
    ))
    self._AssertTryBotExceptions(
        'Failed to run "git cl issue" command.',
        command._GetChangeList)

  def testGetChangeListNoIssues(self):
    temp_file = self._MockTempFile(None, None)
    command, _ = self._SetupTrybotCommand(
        {'linux_perf_bisect': 'stuff'}, 'linux')
    self._ExpectProcesses((
        (['git', 'cl', 'issue', '--json', temp_file],
         (0, 'Issue number: None (None)', None)),
    ))
    self._AssertTryBotExceptions(
        ('PLEASE NOTE: The workflow for Perf Try jobs is changed. '
         'In order to run the perf try job, you must first upload your '
         'changes to rietveld.'),
        command._GetChangeList)

  def testGetChangeListWithIssue(self):
    temp_file = self._MockTempFile(
        12345, 'https://codereview.chromium.org/12345')
    command, _ = self._SetupTrybotCommand(
        {'linux_perf_bisect': 'stuff'}, 'linux')
    self._ExpectProcesses((
        (['git', 'cl', 'issue', '--json', temp_file],
         (0, 'stuff https://codereview.chromium.org/12345 stuff', None)),
    ))
    self.assertEquals('https://codereview.chromium.org/12345',
                      command._GetChangeList())

  def testRunTryJobFailed(self):
    test_args = self._ExpectedGitTryTestArgs('sunspider', 'release')
    command, options = self._SetupTrybotCommand(
        {'linux_perf_bisect': 'stuff'}, 'linux', repo_path='path_to_repo/src')
    arguments = [options.benchmark_name] + []
    self._ExpectProcesses((
        (['git', 'cl', 'try', '-m', 'tryserver.chromium.perf',
          '-p', test_args,
          '-b',
          'linux_perf_bisect'], (128, None, None)),))
    self._AssertTryBotExceptions(
        'Could not try CL for linux',
        command._RunTryJob, 'linux', arguments, None)

  def testRunTryJobWithDepsOverrideFailed(self):
    test_args = self._ExpectedGitTryTestArgs('sunspider', 'release')
    deps_override_arg = 'deps_revision_overrides={"src/v8": "feedbeed"}'

    command, options = self._SetupTrybotCommand(
        {'linux_perf_bisect': 'stuff'}, 'linux', repo_path='path_to_repo/v8',
        deps_revision='feedbeed')
    arguments = [options.benchmark_name] + []
    self._ExpectProcesses((
        (['git', 'cl', 'try', '-m', 'tryserver.chromium.perf',
          '-p', test_args,
          '-p', deps_override_arg,
          '-b',
          'linux_perf_bisect'], (128, None, None)),))
    self._AssertTryBotExceptions(
        'Could not try CL for linux with DEPS override',
        command._RunTryJob, 'linux', arguments, {'src/v8': 'feedbeed'})

  def testRunTryJobSuccess(self):
    test_args = self._ExpectedGitTryTestArgs('sunspider', 'release')
    command, options = self._SetupTrybotCommand(
        {'linux_perf_bisect': 'stuff'}, 'linux', repo_path='path_to_repo/src')
    arguments = [options.benchmark_name] + []
    self._ExpectProcesses((
        (['git', 'cl', 'try', '-m', 'tryserver.chromium.perf',
          '-p', test_args,
          '-b',
          'linux_perf_bisect'], (0, '', None)),))
    command._RunTryJob('linux', arguments, None)
    self.assertEquals('Perf Try job sent to rietveld for linux platform.',
                      sys.stdout.getvalue().strip())

  def testNoUpstream(self):
    command, _ = self._SetupTrybotCommand({'linux_perf_bisect': 'stuff'},
                                          'linux')
    self._ExpectProcesses((
        (['git', 'config', 'branch.br.remote'], (0, '.', None)),
        (['git', 'rev-parse', '--abbrev-ref', 'br@{upstream}'],
         (128, 'None', None,)),
    ))
    self._AssertTryBotExceptions(
        'Failed to get upstream branch name.',
        command._GetBaseGitHashForRepo, 'br', 'http://repo/git/url.git')

  def testGitConfigBranchRemote(self):
    command, _ = self._SetupTrybotCommand({'linux_perf_bisect': 'stuff'},
                                          'linux')
    self._ExpectProcesses((
        (['git', 'config', 'branch.br.remote'],
         (128, 'None', None)),
    ))
    self._AssertTryBotExceptions(
        'Failed to get branch.br.remote from git config',
        command._GetBaseGitHashForRepo, 'br', 'http://repo/git/url.git')

  def testGitConfigBranchRemoteUrl(self):
    command, _ = self._SetupTrybotCommand({'linux_perf_bisect': 'stuff'},
                                          'linux')
    self._ExpectProcesses((
        (['git', 'config', 'branch.br.remote'], (0, '.', None)),
        (['git', 'rev-parse', '--abbrev-ref', 'br@{upstream}'],
         (0, 'br1', None,)),
        (['git', 'config', 'branch.br1.remote'], (0, 'origin', None)),
        (['git', 'config', 'remote.origin.url'], (128, 'None', None)),
    ))
    self._AssertTryBotExceptions(
        'Failed to get remote.origin.url from git config',
        command._GetBaseGitHashForRepo, 'br', 'http://repo/git/url.git')

  def testGetBaseGitHashForRemoteURLMatchFound(self):
    command, _ = self._SetupTrybotCommand({'linux_perf_bisect': 'stuff'},
                                          'linux')
    self._ExpectProcesses((
        (['git', 'config', 'branch.br.remote'],
         (0, '.', None)),
        (['git', 'rev-parse', '--abbrev-ref', 'br@{upstream}'],
         (0, 'br1', None,)),
        (['git', 'config', 'branch.br1.remote'], (0, 'origin', None)),
        (['git', 'config', 'remote.origin.url'],
         (0, 'http://repo/git/url.git', None)),
        (['git', 'rev-parse', 'br1@{upstream}'], (0, 'feedbeed', None)),
    ))
    self.assertEquals(
        command._GetBaseGitHashForRepo('br', 'http://repo/git/url.git'),
        'feedbeed')

  def testGetBaseGitHashForRemoteUrlNoMatchFound(self):
    command, _ = self._SetupTrybotCommand({'linux_perf_bisect': 'stuff'},
                                          'linux')
    self._ExpectProcesses((
        (['git', 'config', 'branch.br.remote'],
         (0, '.', None)),
        (['git', 'rev-parse', '--abbrev-ref', 'br@{upstream}'],
         (0, 'br1', None,)),
        (['git', 'config', 'branch.br1.remote'],
         (0, 'origin', None)),
        (['git', 'config', 'remote.origin.url'],
         (0, 'http://non_maching_repo/git/url.git', None)),
        (['git', 'rev-parse', 'br1@{upstream}'],
         (0, 'feedbeed', None)),
    ))
    self._AssertTryBotExceptions(
        ('URL http://non_maching_repo/git/url.git on remote origin is not '
         'recognized on branch'),
        command._GetBaseGitHashForRepo, 'br', 'http://repo/git/url.git')

  @mock.patch('core.trybot_command.os.chdir', mock.MagicMock())
  @mock.patch('core.trybot_command.os.path.exists',
              mock.MagicMock(return_value=True))
  def testAttemptTryjobForCrRepo(self):
    test_args = self._ExpectedGitTryTestArgs('sunspider', 'release')
    command, options = self._SetupTrybotCommand({'linux_perf_bisect': 'stuff'},
                                                'linux')
    temp_file = self._MockTempFile(
        12345, 'https://codereview.chromium.org/12345')

    self._ExpectProcesses((
        (['git', 'rev-parse', '--abbrev-ref', '--show-toplevel', 'HEAD'],
         (0, '/root/path_to/repo/src\nbr\n', None)),
        (['git', 'update-index', '--refresh', '-q'], (0, '', None,)),
        (['git', 'diff-index', 'HEAD'], (0, '', None)),
        (['git', 'cl', 'issue', '--json', temp_file],
         (0, 'stuff https://codereview.chromium.org/12345 stuff', None)),
        (['git', 'cl', 'try', '-m', 'tryserver.chromium.perf',
          '-p', test_args, '-b', 'linux_perf_bisect'], (0, '', None))
    ))

    with mock.patch('core.trybot_command.os.path.abspath',
                    return_value=trybot_command.CHROMIUM_SRC_PATH):
      command._AttemptTryjob(options, [])

    output = ('Running try job....\n'
              'view progress here https://codereview.chromium.org/12345.\n'
              '\tRepo Name: src\n'
              '\tPath: %s\n'
              '\tBranch: br\n'
              'Perf Try job sent to rietveld for linux platform.') % (
                  options.repo_path)
    self.assertEquals(output, sys.stdout.getvalue().strip())

  @mock.patch('core.trybot_command.os.chdir', mock.MagicMock())
  @mock.patch('core.trybot_command.os.path.exists',
              mock.MagicMock(return_value='True'))
  def testAttemptTryjobAllForCrRepo(self):
    default_config = self._ExpectedGitTryTestArgs('sunspider', 'release')
    winx64_config = self._ExpectedGitTryTestArgs(
        'sunspider', 'release_x64', 'x64')
    android_config = self._ExpectedGitTryTestArgs(
        'sunspider', 'android-chromium', 'ia32')
    command, options = self._SetupTrybotCommand(
        {'linux_perf_bisect': 'stuff',
         'win_perf_bisect': 'stuff',
         'winx64_perf_bisect': 'stuff',
         'android_perf_bisect': 'stuff',
         'mac_perf_bisect': 'stuff'}, 'all')
    temp_file = self._MockTempFile(
        12345, 'https://codereview.chromium.org/12345')

    self._ExpectProcesses((
        (['git', 'rev-parse', '--abbrev-ref', '--show-toplevel', 'HEAD'],
         (0, '/root/path_to/repo/src\nbr\n', None)),
        (['git', 'update-index', '--refresh', '-q'], (0, '', None,)),
        (['git', 'diff-index', 'HEAD'], (0, '', None)),
        (['git', 'cl', 'issue', '--json', temp_file],
         (0, 'stuff https://codereview.chromium.org/12345 stuff', None)),
        (['git', 'cl', 'try', '-m', 'tryserver.chromium.perf',
          '-p', default_config, '-b', 'win_perf_bisect'], (0, '', None)),
        (['git', 'cl', 'try', '-m', 'tryserver.chromium.perf',
          '-p', android_config, '-b', 'android_perf_bisect'], (0, '', None)),
        (['git', 'cl', 'try', '-m', 'tryserver.chromium.perf',
          '-p', winx64_config, '-b', 'winx64_perf_bisect'], (0, '', None)),
        (['git', 'cl', 'try', '-m', 'tryserver.chromium.perf',
          '-p', default_config, '-b', 'mac_perf_bisect'], (0, '', None)),
        (['git', 'cl', 'try', '-m', 'tryserver.chromium.perf',
          '-p', default_config, '-b', 'linux_perf_bisect'], (0, '', None)),
    ))

    with mock.patch('core.trybot_command.os.path.abspath',
                    return_value=trybot_command.CHROMIUM_SRC_PATH):
      command._AttemptTryjob(options, [])

    output = ('Running try job....\n'
              'view progress here https://codereview.chromium.org/12345.\n'
              '\tRepo Name: src\n'
              '\tPath: %s\n'
              '\tBranch: br\n'
              'Perf Try job sent to rietveld for win platform.\n'
              'Perf Try job sent to rietveld for android platform.\n'
              'Perf Try job sent to rietveld for win-x64 platform.\n'
              'Perf Try job sent to rietveld for mac platform.\n'
              'Perf Try job sent to rietveld for linux platform.') % (
                  options.repo_path)
    self.assertEquals(output, sys.stdout.getvalue().strip())

  @mock.patch('core.trybot_command.os.chdir', mock.MagicMock())
  @mock.patch('core.trybot_command.os.path.exists',
              mock.MagicMock(return_value='True'))
  def testAttemptTryjobForDepsRepo(self):
    test_args = self._ExpectedGitTryTestArgs('sunspider', 'release')
    deps_override_arg = 'deps_revision_overrides={"src/v8": "feedbeed"}'
    command, options = self._SetupTrybotCommand(
        {'linux_perf_bisect': 'stuff'}, 'linux',
        repo_path='root/path_to/repo/v8')
    temp_file = self._MockTempFile(
        12345, 'https://codereview.chromium.org/12345')

    self._ExpectProcesses((
        (['git', 'rev-parse', '--abbrev-ref', '--show-toplevel', 'HEAD'],
         (0, 'root/path_to/repo/v8\nbr\n', None)),
        (['git', 'update-index', '--refresh', '-q'], (0, '', None,)),
        (['git', 'diff-index', 'HEAD'], (0, '', None)),
        (['git', 'config', 'branch.br.remote'], (0, '.', None)),
        (['git', 'rev-parse', '--abbrev-ref', 'br@{upstream}'],
         (0, 'br1', None,)),
        (['git', 'config', 'branch.br1.remote'], (0, 'origin', None)),
        (['git', 'config', 'remote.origin.url'],
         (0, 'https://chromium.googlesource.com/v8/v8.git', None)),
        (['git', 'rev-parse', 'br1@{upstream}'], (0, 'feedbeed', None)),
        (['git', 'cl', 'issue', '--json', temp_file],
         (0, 'stuff https://codereview.chromium.org/12345 stuff', None)),
        (['git', 'cl', 'try', '-m', 'tryserver.chromium.perf',
          '-p', test_args, '-p', deps_override_arg,
          '-b', 'linux_perf_bisect'], (0, '', None))
    ))

    with mock.patch('core.trybot_command.os.path.abspath',
                    return_value='root/path_to/repo/v8'):
      command._AttemptTryjob(options, [])

    output = ('Running try job....\n'
              'view progress here https://codereview.chromium.org/12345.\n'
              '\tRepo Name: v8\n'
              '\tPath: root/path_to/repo/v8\n'
              '\tBranch: br\n'
              'Perf Try job sent to rietveld for linux platform.')
    self.assertEquals(output, sys.stdout.getvalue().strip())

  @mock.patch('core.trybot_command.os.chdir', mock.MagicMock())
  @mock.patch('core.trybot_command.os.path.exists',
              mock.MagicMock(return_value='True'))
  def testAttemptTryjobAllForDepsRepo(self):
    default_config = self._ExpectedGitTryTestArgs('sunspider', 'release')
    deps_override_arg = 'deps_revision_overrides={"src/v8": "feedbeed"}'
    winx64_config = self._ExpectedGitTryTestArgs(
        'sunspider', 'release_x64', 'x64')
    android_config = self._ExpectedGitTryTestArgs(
        'sunspider', 'android-chromium', 'ia32')
    command, options = self._SetupTrybotCommand(
        {'linux_perf_bisect': 'stuff',
         'winx64_perf_bisect': 'stuff',
         'android_perf_bisect': 'stuff'},
        'all', repo_path='root/path_to/repo/v8')
    temp_file = self._MockTempFile(
        12345, 'https://codereview.chromium.org/12345')

    self._ExpectProcesses((
        (['git', 'rev-parse', '--abbrev-ref', '--show-toplevel', 'HEAD'],
         (0, 'root/path_to/repo/v8\nbr\n', None)),
        (['git', 'update-index', '--refresh', '-q'], (0, '', None,)),
        (['git', 'diff-index', 'HEAD'], (0, '', None)),
        (['git', 'config', 'branch.br.remote'], (0, '.', None)),
        (['git', 'rev-parse', '--abbrev-ref', 'br@{upstream}'],
         (0, 'br1', None,)),
        (['git', 'config', 'branch.br1.remote'], (0, 'origin', None)),
        (['git', 'config', 'remote.origin.url'],
         (0, 'https://chromium.googlesource.com/v8/v8.git', None)),
        (['git', 'rev-parse', 'br1@{upstream}'],
         (0, 'feedbeed', None)),
        (['git', 'cl', 'issue', '--json', temp_file],
         (0, 'stuff https://codereview.chromium.org/12345 stuff', None)),
        (['git', 'cl', 'try', '-m', 'tryserver.chromium.perf',
          '-p', android_config, '-p', deps_override_arg,
          '-b', 'android_perf_bisect'], (0, '', None)),
        (['git', 'cl', 'try', '-m', 'tryserver.chromium.perf',
          '-p', winx64_config, '-p', deps_override_arg,
          '-b', 'winx64_perf_bisect'], (0, '', None)),
        (['git', 'cl', 'try', '-m', 'tryserver.chromium.perf',
          '-p', default_config, '-p', deps_override_arg,
          '-b', 'linux_perf_bisect'], (0, '', None)),
    ))

    with mock.patch('core.trybot_command.os.path.abspath',
                    return_value='root/path_to/repo/v8'):
      command._AttemptTryjob(options, [])

    output = ('Running try job....\n'
              'view progress here https://codereview.chromium.org/12345.\n'
              '\tRepo Name: v8\n'
              '\tPath: root/path_to/repo/v8\n'
              '\tBranch: br\n'
              'Perf Try job sent to rietveld for android platform.\n'
              'Perf Try job sent to rietveld for win-x64 platform.\n'
              'Perf Try job sent to rietveld for linux platform.')
    self.assertEquals(output, sys.stdout.getvalue().strip())

  @mock.patch('core.trybot_command.os.chdir', mock.MagicMock())
  @mock.patch('core.trybot_command.os.path.exists',
              mock.MagicMock(return_value='True'))
  def testAttemptTryjobWithDepsRevisionArg(self):
    test_args = self._ExpectedGitTryTestArgs('sunspider', 'release')
    deps_override_arg = 'deps_revision_overrides={"src/v8": "feedbeed"}'
    command, options = self._SetupTrybotCommand(
        {'linux_perf_bisect': 'stuff'}, 'linux',
        repo_path='root/path_to/repo/v8', deps_revision='feedbeed')
    temp_file = self._MockTempFile(
        12345, 'https://codereview.chromium.org/12345')

    self._ExpectProcesses((
        (['git', 'rev-parse', '--abbrev-ref', '--show-toplevel', 'HEAD'],
         (0, 'root/path_to/repo/v8\nbr\n', None)),
        (['git', 'update-index', '--refresh', '-q'], (0, '', None,)),
        (['git', 'diff-index', 'HEAD'], (0, '', None)),
        (['git', 'cl', 'issue', '--json', temp_file],
         (0, 'stuff https://codereview.chromium.org/12345 stuff', None)),
        (['git', 'cl', 'try', '-m', 'tryserver.chromium.perf',
          '-p', test_args, '-p', deps_override_arg,
          '-b', 'linux_perf_bisect'], (0, '', None))
    ))
    with mock.patch('core.trybot_command.os.path.abspath',
                    return_value='root/path_to/repo/v8'):
      command._AttemptTryjob(options, [])

    output = ('Running try job....\n'
              'view progress here https://codereview.chromium.org/12345.\n'
              '\tRepo Name: v8\n'
              '\tPath: root/path_to/repo/v8\n'
              '\tBranch: br\n'
              'Perf Try job sent to rietveld for linux platform.')
    self.assertEquals(output, sys.stdout.getvalue().strip())


class IsBenchmarkDisabledOnTrybotPlatformTest(unittest.TestCase):

  def IsBenchmarkDisabled(self, benchmark_class, trybot_name):
    return trybot_command.Trybot.IsBenchmarkDisabledOnTrybotPlatform(
        benchmark_class, trybot_name)[0]

  def testBenchmarkIsDisabledAll(self):
    @benchmark.Disabled('all')
    class FooBenchmark(benchmark.Benchmark):
      pass
    self.assertTrue(self.IsBenchmarkDisabled(FooBenchmark, 'all'))
    self.assertTrue(self.IsBenchmarkDisabled(FooBenchmark, 'all-mac'))
    self.assertTrue(self.IsBenchmarkDisabled(FooBenchmark, 'android-s5'))
    self.assertTrue(self.IsBenchmarkDisabled(FooBenchmark, 'linux'))
    self.assertTrue(self.IsBenchmarkDisabled(FooBenchmark, 'winx64ati'))

  def testBenchmarkIsEnabledAll(self):
    @benchmark.Enabled('all')
    class FooBenchmark(benchmark.Benchmark):
      pass
    self.assertFalse(self.IsBenchmarkDisabled(FooBenchmark, 'all'))
    self.assertFalse(self.IsBenchmarkDisabled(FooBenchmark, 'all-mac'))
    self.assertFalse(self.IsBenchmarkDisabled(FooBenchmark, 'android-s5'))
    self.assertFalse(self.IsBenchmarkDisabled(FooBenchmark, 'linux'))
    self.assertFalse(self.IsBenchmarkDisabled(FooBenchmark, 'winx64ati'))

  def testBenchmarkIsDisabledOnMultiplePlatforms(self):
    @benchmark.Disabled('win', 'mac')
    class FooBenchmark(benchmark.Benchmark):
      pass
    self.assertFalse(self.IsBenchmarkDisabled(FooBenchmark, 'all'))
    self.assertFalse(self.IsBenchmarkDisabled(FooBenchmark, 'android-s5'))
    self.assertFalse(self.IsBenchmarkDisabled(FooBenchmark, 'linux'))

    self.assertTrue(self.IsBenchmarkDisabled(FooBenchmark, 'all-mac'))
    self.assertTrue(self.IsBenchmarkDisabled(FooBenchmark, 'winx64ati'))

  def testBenchmarkIsEnabledOnMultiplePlatforms(self):
    @benchmark.Enabled('win', 'mac')
    class FooBenchmark(benchmark.Benchmark):
      pass
    self.assertFalse(self.IsBenchmarkDisabled(FooBenchmark, 'all'))
    self.assertFalse(self.IsBenchmarkDisabled(FooBenchmark, 'all-mac'))
    self.assertFalse(self.IsBenchmarkDisabled(FooBenchmark, 'winx64ati'))

    self.assertTrue(self.IsBenchmarkDisabled(FooBenchmark, 'android-s5'))
    self.assertTrue(self.IsBenchmarkDisabled(FooBenchmark, 'linux'))
    self.assertTrue(self.IsBenchmarkDisabled(FooBenchmark, 'all-linux'))
