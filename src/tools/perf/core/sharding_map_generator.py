# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Script to generate benchmark_sharding_map.json in the //tools/perf/core
directory. This file controls which bots run which tests.

The file is a JSON dictionary. It maps waterfall name to a mapping of benchmark
to bot id. E.g.

{
  "build1-b1": {
    "benchmarks": [
      "battor.steady_state",
      ...
    ],
  }
}

This will be used to manually shard tests to certain bots, to more efficiently
execute all our tests.
"""

import argparse
import json
import os

from core import path_util
path_util.AddTelemetryToPath()

from telemetry.util import bot_utils


def get_sharding_map_path():
  return os.path.join(
      path_util.GetChromiumSrcDir(), 'tools', 'perf', 'core',
      'benchmark_sharding_map.json')


def load_benchmark_sharding_map():
  with open(get_sharding_map_path()) as f:
    raw = json.load(f)

  # The raw json format is easy for people to modify, but isn't what we want
  # here. Change it to map builder -> benchmark -> device.
  final_map = {}
  for builder, builder_map in raw.items():
    if builder == 'all_benchmarks':
      continue

    final_builder_map = {}
    for device, device_value in builder_map.items():
      for benchmark_name in device_value['benchmarks']:
        final_builder_map[benchmark_name] = device
    final_map[builder] = final_builder_map

  return final_map


# Returns a sorted list of (benchmark, avg_runtime) pairs for every
# benchmark in the all_benchmarks list where avg_runtime is in seconds.  Also
# returns a list of benchmarks whose run time have not been seen before
def get_sorted_benchmark_list_by_time(all_benchmarks):
  runtime_list = []
  benchmark_avgs = {}
  new_benchmarks = []
  timing_file_path = os.path.join(
      path_util.GetChromiumSrcDir(), 'tools', 'perf', 'core',
      'desktop_benchmark_avg_times.json')
  # Load in the avg times as calculated on Nov 1st, 2016
  with open(timing_file_path) as f:
    benchmark_avgs = json.load(f)

  for benchmark in all_benchmarks:
    benchmark_avg_time = benchmark_avgs.get(benchmark.Name(), None)
    if benchmark_avg_time is None:
      # Assume that this is a new benchmark that was added after 11/1/16 when
      # we generated the benchmarks. Use the old affinity algorithm after
      # we have given the rest the same distribution, add it to the
      # new benchmarks list.
      new_benchmarks.append(benchmark)
    else:
      # Need to multiple the seconds by 2 since we will be generating two tests
      # for each benchmark to be run on the same shard for the reference build
      runtime_list.append((benchmark, benchmark_avg_time * 2.0))

  # Return a reverse sorted list by runtime
  runtime_list.sort(key=lambda tup: tup[1], reverse=True)
  return runtime_list, new_benchmarks


# Returns a map of benchmark name to shard it is on.
def shard_benchmarks(num_shards, all_benchmarks):
  benchmark_to_shard_dict = {}
  shard_execution_times = [0] * num_shards
  sorted_benchmark_list, new_benchmarks = get_sorted_benchmark_list_by_time(
    all_benchmarks)
  # Iterate over in reverse order and add them to the current smallest bucket.
  for benchmark in sorted_benchmark_list:
    # Find current smallest bucket
    min_index = shard_execution_times.index(min(shard_execution_times))
    benchmark_to_shard_dict[benchmark[0].Name()] = min_index
    shard_execution_times[min_index] += benchmark[1]
  # For all the benchmarks that didn't have avg run times, use the default
  # device affinity algorithm
  for benchmark in new_benchmarks:
     device_affinity = bot_utils.GetDeviceAffinity(num_shards, benchmark.Name())
     benchmark_to_shard_dict[benchmark.Name()] = device_affinity
  return benchmark_to_shard_dict


def regenerate(benchmarks, waterfall_configs, buildernames=None):
  """Regenerate the shard mapping file.

  This overwrites the current file with fresh data.
  """
  with open(get_sharding_map_path()) as f:
    sharding_map = json.load(f)
  sharding_map[u'all_benchmarks'] = [b.Name() for b in benchmarks]

  for name, config in waterfall_configs.items():
    for buildername, tester in config['testers'].items():
      if not tester.get('swarming'):
        continue

      if buildernames and buildername not in buildernames:
        continue
      per_builder = {}

      devices = tester['swarming_dimensions'][0]['device_ids']
      shard_number = len(devices)
      shard = shard_benchmarks(shard_number, benchmarks)

      for name, index in shard.items():
        device = devices[index]
        device_map = per_builder.get(device, {'benchmarks': []})
        device_map['benchmarks'].append(name)
        per_builder[device] = device_map
      sharding_map[buildername] = per_builder


  for name, builder_values in sharding_map.items():
    if name == 'all_benchmarks':
      builder_values.sort()
      continue

    for value in builder_values.values():
      value['benchmarks'].sort()

  with open(get_sharding_map_path(), 'w') as f:
    json.dump(sharding_map, f, indent=2, sort_keys=True, separators=(',', ': '))

  return 0


def get_args():
  parser = argparse.ArgumentParser(
      description=('Generate perf test sharding map.'
                   'This needs to be done anytime you add/remove any existing'
                   'benchmarks in tools/perf/benchmarks.'))

  parser.add_argument('mode', choices=['regenerate'])
  parser.add_argument('--buildernames', '-b', action='append', default=None)
  return parser


def main(args, benchmarks, configs):
  if args.mode == 'regenerate':
    return regenerate(benchmarks, configs, args.buildernames)
