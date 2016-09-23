# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from optparse import OptionParser
import unittest

from telemetry.page import shared_page_state

from benchmarks import rasterize_and_record_micro
from benchmarks import repaint
from benchmarks import skpicture_printer


class MockErrorParser(object):

  def __init__(self):
    self.err_msg = None

  def error(self, err_msg):
    self.err_msg = err_msg


class CTBenchmarks(unittest.TestCase):

  def setUp(self):
    self.ct_benchmarks = [
        rasterize_and_record_micro.RasterizeAndRecordMicroCT(),
        repaint.RepaintCT(),
        skpicture_printer.SkpicturePrinterCT(),
    ]
    self.shared_page_state_class = shared_page_state.SharedMobilePageState
    self.archive_data_file = '/b/test'
    self.urls_list = 'http://test1.com,http://test2.com,http://test3.net'
    self.mock_parser = MockErrorParser()

  def testCTBenchmarks(self):
    for benchmark in self.ct_benchmarks:
      parser = OptionParser()
      parser.user_agent = 'mobile'
      parser.archive_data_file = self.archive_data_file
      parser.urls_list = self.urls_list

      benchmark.AddBenchmarkCommandLineArgs(parser)
      benchmark.ProcessCommandLineArgs(None, parser)
      ct_page_set = benchmark.CreateStorySet(parser)

      self.assertEquals(
          len(self.urls_list.split(',')), len(ct_page_set.stories))
      self.assertEquals(
          self.archive_data_file, ct_page_set.archive_data_file)
      for i in range(len(self.urls_list.split(','))):
        url = self.urls_list.split(',')[i]
        story = ct_page_set.stories[i]
        self.assertEquals(url, story.url)
        self.assertEquals(
            self.shared_page_state_class, story.shared_state_class)
        self.assertEquals(self.archive_data_file, story.archive_data_file)

  def testCTBenchmarks_wrongAgent(self):
    for benchmark in self.ct_benchmarks:
      parser = OptionParser()
      parser.user_agent = 'mobileeeeee'
      parser.archive_data_file = self.archive_data_file
      parser.urls_list = self.urls_list

      benchmark.AddBenchmarkCommandLineArgs(parser)
      benchmark.ProcessCommandLineArgs(None, parser)
      try:
        benchmark.CreateStorySet(parser)
        self.fail('Expected ValueError')
      except ValueError, e:
        self.assertEquals('user_agent mobileeeeee is unrecognized', e.message)

  def testCTBenchmarks_missingDataFile(self):
    for benchmark in self.ct_benchmarks:
      parser = OptionParser()
      parser.user_agent = 'mobile'
      parser.urls_list = self.urls_list
      benchmark.AddBenchmarkCommandLineArgs(parser)

      # Should fail due to missing archive_data_file.
      try:
        benchmark.ProcessCommandLineArgs(None, parser)
        self.fail('Expected AttributeError')
      except AttributeError, e:
        self.assertEquals(
            'OptionParser instance has no attribute \'archive_data_file\'',
            e.message)

      # Now add an empty archive_data_file.
      parser.archive_data_file = ''
      benchmark.ProcessCommandLineArgs(self.mock_parser, parser)
      self.assertEquals(
          'Please specify --archive_data_file.', self.mock_parser.err_msg)

  def testCTBenchmarks_missingUrlsList(self):
    for benchmark in self.ct_benchmarks:
      parser = OptionParser()
      parser.user_agent = 'mobile'
      parser.archive_data_file = self.archive_data_file
      benchmark.AddBenchmarkCommandLineArgs(parser)

      # Should fail due to missing urls_list.
      try:
        benchmark.ProcessCommandLineArgs(None, parser)
        self.fail('Expected AttributeError')
      except AttributeError, e:
        self.assertEquals(
            'OptionParser instance has no attribute \'urls_list\'',
            e.message)

      # Now add an empty urls_list.
      parser.urls_list = ''
      benchmark.ProcessCommandLineArgs(self.mock_parser, parser)
      self.assertEquals('Please specify --urls_list.', self.mock_parser.err_msg)
