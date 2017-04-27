#!/usr/bin/env python
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Wrapper for adding logdog streaming support to swarming tasks."""

import argparse
import logging
import os
import signal
import subprocess
import sys

_SRC_PATH = os.path.abspath(os.path.join(
    os.path.dirname(__file__), '..', '..', '..'))
sys.path.append(os.path.join(_SRC_PATH, 'third_party', 'catapult', 'devil'))
sys.path.append(os.path.join(_SRC_PATH, 'third_party', 'catapult', 'common',
                             'py_utils'))

from devil.utils import signal_handler
from py_utils import tempfile_ext

PROJECT = 'chromium'
OUTPUT = 'logdog'
COORDINATOR_HOST = 'luci-logdog.appspot.com'
SERVICE_ACCOUNT_JSON = ('/creds/service_accounts'
                        '/service-account-luci-logdog-publisher.json')

def CommandParser():
  # Parses the command line arguments being passed in
  parser = argparse.ArgumentParser()
  parser.add_argument('--target', required=True,
                      help='The test target to be run.')
  parser.add_argument('--logdog-bin-cmd', required=True,
                      help='The logdog bin cmd.')
  parser.add_argument('--target-devices-file', required=False,
                      help='The target devices file.')
  parser.add_argument('--logcat-output-file',
                      help='The logcat output file.')
  return parser

def CreateStopTestsMethod(proc):
  def StopTests(signum, _frame):
    logging.error('Forwarding signal %s to test process', str(signum))
    proc.send_signal(signum)
  return StopTests

def main():
  parser = CommandParser()
  args, extra_cmd_args = parser.parse_known_args(sys.argv[1:])

  logging.basicConfig(level=logging.INFO)
  with tempfile_ext.NamedTemporaryDirectory() as logcat_output_dir:
    test_cmd = [
        os.path.join('bin', 'run_%s' % args.target),
        '--logcat-output-file',
        (args.logcat_output_file if args.logcat_output_file
            else os.path.join(logcat_output_dir, 'logcats')),
        '--target-devices-file', args.target_devices_file,
        '-v']

    with tempfile_ext.NamedTemporaryDirectory(
        prefix='tmp_android_logdog_wrapper') as temp_directory:
      if not os.path.exists(args.logdog_bin_cmd):
        logging.error(
            'Logdog binary %s unavailable. Unable to create logdog client',
            args.logdog_bin_cmd)
      else:
        test_cmd += ['--upload-logcats-file']
        streamserver_uri = 'unix:%s' % os.path.join(temp_directory,
                                                    'butler.sock')
        prefix = os.path.join('android', 'swarming', 'logcats',
                              os.environ.get('SWARMING_TASK_ID'))

        # Call test_cmdline through logdog butler subcommand.
        test_cmd = [
            args.logdog_bin_cmd, '-project', PROJECT,
            '-output', OUTPUT,
            '-prefix', prefix,
            '--service-account-json', SERVICE_ACCOUNT_JSON,
            '-coordinator-host', COORDINATOR_HOST,
            'run', '-streamserver-uri', streamserver_uri, '--'] + test_cmd

      test_cmd += extra_cmd_args
      test_proc = subprocess.Popen(test_cmd)
      with signal_handler.SignalHandler(signal.SIGTERM,
                                        CreateStopTestsMethod(test_proc)):
        result = test_proc.wait()
    return result

if __name__ == '__main__':
  sys.exit(main())
