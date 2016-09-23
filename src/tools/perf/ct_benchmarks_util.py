#!/usr/bin/env python
# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.


def AddBenchmarkCommandLineArgs(parser):
  parser.add_option('--user-agent',  action='store', type='string',
                    default=None, help='Options are mobile and desktop.')
  parser.add_option('--archive-data-file',  action='store', type='string',
                    default=None,
                    help='The location of the WPR JSON archive file.')
  parser.add_option('--urls-list',  action='store', type='string',
                    default=None,
                    help='This is a comma separated list of urls. '
                    'Eg: http://www.google.com,http://www.gmail.com')


def ValidateCommandLineArgs(parser, args):
  if not args.user_agent:
    parser.error('Please specify --user_agent.')
  if not args.archive_data_file:
    parser.error('Please specify --archive_data_file.')
  if not args.urls_list:
    parser.error('Please specify --urls_list.')
