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
import urllib


def CommandParser():
  # Parses the command line arguments being passed in
  parser = argparse.ArgumentParser()
  parser.add_argument('--logdog-bin-cmd', required=True,
                      help='Command for running logdog butler binary')
  parser.add_argument('--project', required=True,
                      help='Name of logdog project')
  parser.add_argument('--logdog-server',
                      default='services-dot-luci-logdog.appspot.com',
                      help='URL of logdog server, https:// is assumed.')
  parser.add_argument('--service-account-json', required=True,
                      help='Location of authentication json')
  parser.add_argument('--prefix', required=True,
                      help='Prefix to be used for logdog stream')
  parser.add_argument('--source', required=True,
                      help='Location of file for logdog to stream')
  parser.add_argument('--name', required=True,
                      help='Name to be used for logdog stream')
  return parser


def CreateUrl(server, project, prefix, name):
  stream_name = '%s/%s/+/%s' % (project, prefix, name)
  return 'https://%s/v/?s=%s' % (server, urllib.quote_plus(stream_name))


def CreateSignalForwarder(proc):
  def handler(signum, _frame):
    logging.error('Forwarding signal %s to test process', str(signum))
    proc.send_signal(signum)

  return handler


def main():
  parser = CommandParser()
  args, test_cmd = parser.parse_known_args(sys.argv[1:])
  logging.basicConfig(level=logging.INFO)
  if not test_cmd:
    parser.error('Must specify command to run after the logdog flags')
  test_proc = subprocess.Popen(test_cmd)
  original_sigterm_handler = signal.signal(
      signal.SIGTERM, CreateSignalForwarder(test_proc))
  try:
    result = test_proc.wait()
  finally:
    signal.signal(signal.SIGTERM, original_sigterm_handler)
  if '${SWARMING_TASK_ID}' in args.prefix:
    args.prefix = args.prefix.replace('${SWARMING_TASK_ID}',
                                      os.environ.get('SWARMING_TASK_ID'))
  url = CreateUrl('luci-logdog.appspot.com', args.project, args.prefix,
                  args.name)
  logdog_cmd = [args.logdog_bin_cmd, '-project', args.project,
                '-output', 'logdog,host=%s' % args.logdog_server,
                '-prefix', args.prefix,
                '-service-account-json', args.service_account_json,
                'stream', '-source', args.source,
                '-stream', '-name=%s' % args.name]

  if not os.path.exists(args.logdog_bin_cmd):
    logging.error(
        'Logdog binary %s unavailable. Unable to upload logcats.',
        args.logdog_bin_cmd)
  elif not os.path.exists(args.source):
    logging.error(
        'Logcat sources not found at %s. Unable to upload logcats.',
        args.source)
  else:
    subprocess.call(logdog_cmd)
    logging.info('Logcats are located at: %s', url)
  return result


if __name__ == '__main__':
  sys.exit(main())
