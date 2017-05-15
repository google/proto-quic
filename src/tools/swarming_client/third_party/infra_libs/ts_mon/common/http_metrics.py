# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from infra_libs.ts_mon.common import metrics


# Extending HTTP status codes to client-side errors and timeouts.
STATUS_OK = 200
STATUS_ERROR = 901
STATUS_TIMEOUT = 902
STATUS_EXCEPTION = 909

request_bytes = metrics.CumulativeDistributionMetric('http/request_bytes',
    'Bytes sent per http request (body only).', [
        metrics.StringField('name'),
        metrics.StringField('client'),
    ])
response_bytes = metrics.CumulativeDistributionMetric('http/response_bytes',
    'Bytes received per http request (content only).', [
        metrics.StringField('name'),
        metrics.StringField('client'),
    ])
durations = metrics.CumulativeDistributionMetric('http/durations',
    'Time elapsed between sending a request and getting a'
    ' response (including parsing) in milliseconds.', [
        metrics.StringField('name'),
        metrics.StringField('client'),
    ])
response_status = metrics.CounterMetric('http/response_status',
    'Number of responses received by HTTP status code.', [
        metrics.IntegerField('status'),
        metrics.StringField('name'),
        metrics.StringField('client'),
    ])


server_request_bytes = metrics.CumulativeDistributionMetric(
    'http/server_request_bytes',
    'Bytes received per http request (body only).', [
        metrics.IntegerField('status'),
        metrics.StringField('name'),
        metrics.BooleanField('is_robot'),
    ])
server_response_bytes = metrics.CumulativeDistributionMetric(
    'http/server_response_bytes',
    'Bytes sent per http request (content only).', [
        metrics.IntegerField('status'),
        metrics.StringField('name'),
        metrics.BooleanField('is_robot'),
    ])
server_durations = metrics.CumulativeDistributionMetric('http/server_durations',
    'Time elapsed between receiving a request and sending a'
    ' response (including parsing) in milliseconds.', [
        metrics.IntegerField('status'),
        metrics.StringField('name'),
        metrics.BooleanField('is_robot'),
    ])
server_response_status = metrics.CounterMetric('http/server_response_status',
    'Number of responses sent by HTTP status code.', [
        metrics.IntegerField('status'),
        metrics.StringField('name'),
        metrics.BooleanField('is_robot'),
    ])


def update_http_server_metrics(endpoint_name, response_status_code, elapsed_ms,
                               request_size=None, response_size=None,
                               user_agent=None):
  fields = {'status': response_status_code, 'name': endpoint_name,
            'is_robot': False}
  if user_agent is not None:
    # We must not log user agents, but we can store whether or not the
    # user agent string indicates that the requester was a Google bot.
    fields['is_robot'] = (
        'GoogleBot' in user_agent or
        'GoogleSecurityScanner' in user_agent or
        user_agent == 'B3M/prober')

  server_durations.add(elapsed_ms, fields=fields)
  server_response_status.increment(fields=fields)
  if request_size is not None:
    server_request_bytes.add(request_size, fields=fields)
  if response_size is not None:
    server_response_bytes.add(response_size, fields=fields)
