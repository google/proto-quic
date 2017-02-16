#! /usr/bin/env python
#
# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import argparse
import collections
import json
import os
import sys

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.abspath(os.path.join(
    CURRENT_DIR, '..', '..', '..', '..', '..'))
sys.path.append(os.path.join(BASE_DIR, 'third_party'))
import jinja2  # pylint: disable=import-error
JINJA_ENVIRONMENT = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
    autoescape=True)


def cell(data, html_class='center'):
  """Formats table cell data for processing in jinja template."""
  return {
    'data': data,
    'class': html_class,
  }


def pre_cell(data, html_class='center'):
  """Formats table <pre> cell data for processing in jinja template."""
  return {
    'cell_type': 'pre',
    'data': data,
    'class': html_class,
  }


class LinkTarget(object):
  # Opens the linked document in a new window or tab.
  NEW_TAB = '_blank'
  # Opens the linked document in the same frame as it was clicked.
  CURRENT_TAB = '_self'


def link(data, href, target=LinkTarget.CURRENT_TAB):
  """Formats <a> tag data for processing in jinja template.

  Args:
    data: String link appears as on HTML page.
    href: URL where link goes.
    target: Where link should be opened (e.g. current tab or new tab).
  """
  return {
    'data': data,
    'href': href,
    'target': target,
  }


def links_cell(links, html_class='center', rowspan=None):
  """Formats table cell with links for processing in jinja template.

  Args:
    links: List of link dictionaries. Use |link| function to generate them.
    html_class: Class for table cell.
    rowspan: Rowspan HTML attribute.
  """
  return {
    'cell_type': 'links',
    'class': html_class,
    'links': links,
    'rowspan': rowspan,
  }


def logs_cell(result):
  """Formats result logs data for processing in jinja template."""
  link_list = []
  for name, href in result.get('links', {}).iteritems():
    link_list.append(link(
        data=name,
        href=href,
        target=LinkTarget.NEW_TAB))

  if link_list:
    return links_cell(link_list)
  else:
    return cell('(no logs)')


def code_search(test, cs_base_url):
  """Returns URL for test on codesearch."""
  search = test.replace('#', '.')
  return '%s/?q=%s&type=cs' % (cs_base_url, search)


def status_class(status):
  """Returns HTML class for test status."""
  status = status.lower()
  if status not in ('success', 'skipped'):
    return 'failure %s' % status
  return status


def create_test_table(results_dict, cs_base_url):
  """Format test data for injecting into HTML table."""

  header_row = [
    cell(data='test_name', html_class='text'),
    cell(data='status', html_class='flaky'),
    cell(data='elapsed_time_ms', html_class='number'),
    cell(data='logs', html_class='text'),
    cell(data='output_snippet', html_class='text'),
  ]

  test_row_blocks = []
  for test_name, test_results in results_dict.iteritems():
    test_runs = []
    for index, result in enumerate(test_results):
      if index == 0:
        test_run = [links_cell(
            links=[
                link(href=code_search(test_name, cs_base_url),
                     target=LinkTarget.NEW_TAB,
                     data=test_name)],
            rowspan=len(test_results),
            html_class='left %s' % test_name
        )]                                        # test_name
      else:
        test_run = []

      test_run.extend([
          cell(data=result['status'],             # status
               html_class=('center %s' %
                  status_class(result['status']))),
          cell(data=result['elapsed_time_ms']),   # elapsed_time_ms
          logs_cell(result),                      # logs
          pre_cell(data=result['output_snippet'], # output_snippet
                   html_class='left'),
      ])
      test_runs.append(test_run)
    test_row_blocks.append(test_runs)
  return header_row, test_row_blocks


def create_suite_table(results_dict):
  """Format test suite data for injecting into HTML table."""

  SUCCESS_COUNT_INDEX = 1
  FAIL_COUNT_INDEX = 2
  ALL_COUNT_INDEX = 3
  TIME_INDEX = 4

  header_row = [
    cell(data='suite_name', html_class='text'),
    cell(data='number_success_tests', html_class='number'),
    cell(data='number_fail_tests', html_class='number'),
    cell(data='all_tests', html_class='number'),
    cell(data='elapsed_time_ms', html_class='number'),
  ]

  footer_row = [
    links_cell(
        links=[
            link(href=('?suite=%s' % 'TOTAL'),
                 target=LinkTarget.CURRENT_TAB,
                 data='TOTAL')
        ],
    ),             # suite_name
    cell(data=0),  # number_success_tests
    cell(data=0),  # number_fail_tests
    cell(data=0),  # all_tests
    cell(data=0),  # elapsed_time_ms
  ]

  suite_row_dict = {}
  for test_name, test_results in results_dict.iteritems():
    # TODO(mikecase): This logic doesn't work if there are multiple test runs.
    # That is, if 'per_iteration_data' has multiple entries.
    # Since we only care about the result of the last test run.
    result = test_results[-1]

    suite_name = (test_name.split('#')[0] if '#' in test_name
                  else test_name.split('.')[0])
    if suite_name in suite_row_dict:
      suite_row = suite_row_dict[suite_name]
    else:
      suite_row = [
        links_cell(
            links=[
                link(href=('?suite=%s' % suite_name),
                     target=LinkTarget.CURRENT_TAB,
                     data=suite_name)],
            html_class='left'
        ),             # suite_name
        cell(data=0),  # number_success_tests
        cell(data=0),  # number_fail_tests
        cell(data=0),  # all_tests
        cell(data=0),  # elapsed_time_ms
      ]

    suite_row_dict[suite_name] = suite_row

    suite_row[ALL_COUNT_INDEX]['data'] += 1
    footer_row[ALL_COUNT_INDEX]['data'] += 1

    if result['status'] == 'SUCCESS':
      suite_row[SUCCESS_COUNT_INDEX]['data'] += 1
      footer_row[SUCCESS_COUNT_INDEX]['data'] += 1
    elif result['status'] != 'SKIPPED':
      suite_row[FAIL_COUNT_INDEX]['data'] += 1
      footer_row[FAIL_COUNT_INDEX]['data'] += 1

    suite_row[TIME_INDEX]['data'] += result['elapsed_time_ms']
    footer_row[TIME_INDEX]['data'] += result['elapsed_time_ms']

  for suite in suite_row_dict.values():
    if suite[FAIL_COUNT_INDEX]['data'] > 0:
      suite[FAIL_COUNT_INDEX]['class'] += ' failure'
    else:
      suite[FAIL_COUNT_INDEX]['class'] += ' success'

  if footer_row[FAIL_COUNT_INDEX]['data'] > 0:
    footer_row[FAIL_COUNT_INDEX]['class'] += ' failure'
  else:
    footer_row[FAIL_COUNT_INDEX]['class'] += ' success'

  return (header_row,
          [[suite_row] for suite_row in suite_row_dict.values()],
          footer_row)


def results_to_html(results_dict, cs_base_url, master_name):
  """Convert list of test results into html format."""

  test_rows_header, test_rows = create_test_table(results_dict, cs_base_url)
  suite_rows_header, suite_rows, suite_row_footer = create_suite_table(
      results_dict)

  suite_table_values = {
    'table_id': 'suite-table',
    'table_headers': suite_rows_header,
    'table_row_blocks': suite_rows,
    'table_footer': suite_row_footer,
  }

  test_table_values = {
    'table_id': 'test-table',
    'table_headers': test_rows_header,
    'table_row_blocks': test_rows,
  }

  main_template = JINJA_ENVIRONMENT.get_template(
      os.path.join('template', 'main.html'))
  return main_template.render(  #  pylint: disable=no-member
      {'tb_values': [suite_table_values, test_table_values],
       'master_name': master_name})


def result_details(json_path, cs_base_url, master_name):
  """Get result details from json path and then convert results to html."""

  with open(json_path) as json_file:
    json_object = json.loads(json_file.read())

  if not 'per_iteration_data' in json_object:
    return 'Error: json file missing per_iteration_data.'

  results_dict = collections.defaultdict(list)
  for testsuite_run in json_object['per_iteration_data']:
    for test, test_runs in testsuite_run.iteritems():
      results_dict[test].extend(test_runs)
  return results_to_html(results_dict, cs_base_url, master_name)


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('--json-file', help='Path of json file.', required=True)
  parser.add_argument('--cs-base-url', help='Base url for code search.',
                      default='http://cs.chromium.org')
  parser.add_argument('--master-name', help='Master name in urls.')

  args = parser.parse_args()
  if os.path.exists(args.json_file):
    result_html_string = result_details(args.json_file, args.cs_base_url,
                                        args.master_name)
    print result_html_string.encode('UTF-8')
  else:
    raise IOError('--json-file %s not found.' % args.json_file)


if __name__ == '__main__':
  sys.exit(main())
