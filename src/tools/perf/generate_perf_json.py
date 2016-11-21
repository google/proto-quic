#!/usr/bin/env python
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Script to generate chromium.perf.json and chromium.perf.fyi.json in
the src/testing/buildbot directory. Maintaining these files by hand is
too unwieldy.
"""

import json
import os
import sys

from chrome_telemetry_build import chromium_config

sys.path.append(chromium_config.GetTelemetryDir())
from telemetry import benchmark as benchmark_module
from telemetry.core import discover
from telemetry.util import bot_utils


SCRIPT_TESTS = [
  {
    'args': [
      'gpu_perftests',
      '--adb-path',
      'src/third_party/catapult/devil/bin/deps/linux2/x86_64/bin/adb',
    ],
    'name': 'gpu_perftests',
    'script': 'gtest_perf_test.py',
    'testers': {
      'chromium.perf': [
        {
          'name': 'Android Nexus5 Perf',
          'shards': [2]
        },
        {
          'name': 'Android Nexus7v2 Perf',
          'shards': [2]
        }
        # crbug.com/663762
        #{
        #  'name': 'Android Nexus9 Perf',
        #  'shards': [2]
        #}
      ],
    }
  },
  {
    'args': [
      'cc_perftests',
      '--adb-path',
      'src/third_party/catapult/devil/bin/deps/linux2/x86_64/bin/adb',
    ],
    'name': 'cc_perftests',
    'script': 'gtest_perf_test.py',
    'testers': {
      'chromium.perf': [
        {
          'name': 'Android Nexus5 Perf',
          'shards': [2]
        },
        {
          'name': 'Android Nexus6 Perf',
          'shards': [2]
        },
        {
          'name': 'Android Nexus7v2 Perf',
          'shards': [2]
        },
        {
          'name': 'Android Nexus9 Perf',
          'shards': [2]
        },
      ],
    }
  },
  {
    'args': [
      'cc_perftests',
      '--test-launcher-print-test-stdio=always'
    ],
    'name': 'cc_perftests',
    'script': 'gtest_perf_test.py',
    'testers': {
      'chromium.perf': [
        {
          'name': 'Linux Perf',
          'shards': [3]
        },
      ]
    }
  },
  {
    'args': [
      'tracing_perftests',
      '--test-launcher-print-test-stdio=always'
    ],
    'name': 'tracing_perftests',
    'script': 'gtest_perf_test.py',
    'testers': {
      'chromium.perf': [
        {
          'name': 'Linux Perf',
          'shards': [3]
        },
      ]
    }
  },
  {
    'args': [
      'load_library_perf_tests',
      '--test-launcher-print-test-stdio=always'
    ],
    'name': 'load_library_perf_tests',
    'script': 'gtest_perf_test.py',
    'testers': {
      'chromium.perf': [
        {
          'name': 'Linux Perf',
          'shards': [3]
        },
        {
          'name': 'Win 7 ATI GPU Perf',
          'shards': [2]
        },
        {
          'name': 'Win 7 Nvidia GPU Perf',
          'shards': [2]
        },
        {
          'name': 'Win 7 Perf',
          'shards': [3]
        },
        {
          'name': 'Win 7 x64 Perf',
          'shards': [2]
        },
        {
          'name': 'Win 8 Perf',
          'shards': [2]
        },
      ]
    }
  },
  {
    'args': [
      'performance_browser_tests',
      '--test-launcher-print-test-stdio=always',
      '--gtest_filter=TabCapturePerformanceTest.*:CastV2PerformanceTest.*',
      '--test-launcher-jobs=1',
      '--enable-gpu'
    ],
    'name': 'performance_browser_tests',
    'script': 'gtest_perf_test.py',
    'testers': {
      'chromium.perf': [
        {
          'name': 'Mac 10.8 Perf',
          'shards': [3]
        },
        {
          'name': 'Mac 10.9 Perf',
          'shards': [3]
        },
        {
          'name': 'Win 7 ATI GPU Perf',
          'shards': [2]
        },
        {
          'name': 'Win 7 Nvidia GPU Perf',
          'shards': [2]
        },
        {
          'name': 'Win 7 Perf',
          'shards': [3]
        },
        {
          'name': 'Win 7 x64 Perf',
          'shards': [2]
        },
        {
          'name': 'Win 8 Perf',
          'shards': [2]
        },
      ]
    }
  },
  {
    'args': [
      'angle_perftests',
      '--test-launcher-print-test-stdio=always',
      '--test-launcher-jobs=1'
    ],
    'name': 'angle_perftests',
    'script': 'gtest_perf_test.py',
    'testers': {
      'chromium.perf': [
        {
          'name': 'Win 7 ATI GPU Perf',
          'shards': [2]
        },
        {
          'name': 'Win 7 Nvidia GPU Perf',
          'shards': [2]
        },
      ]
    }
  },
]


def add_tester(waterfall, name, perf_id, platform, target_bits=64,
              num_host_shards=1, num_device_shards=1, swarming=None,
              use_whitelist=False):
  del perf_id # this will be needed
  waterfall['testers'][name] = {
    'platform': platform,
    'num_device_shards': num_device_shards,
    'num_host_shards': num_host_shards,
    'target_bits': target_bits,
    'use_whitelist': use_whitelist
  }

  if swarming:
    waterfall['testers'][name]['swarming_dimensions'] = swarming
    waterfall['testers'][name]['swarming'] = True

  return waterfall


def get_fyi_waterfall_config():
  waterfall = {'builders':[], 'testers': {}}
  waterfall = add_tester(
    waterfall, 'Win 10 Low-End Perf Tests',
    'win-10-low-end', 'win',
    swarming=[
      {
       'gpu': '1002:9874',
       'os': 'Windows-10-10586',
       'device_ids': [
           'build171-b4', 'build186-b4', 'build202-b4', 'build203-b4',
           'build204-b4', 'build205-b4', 'build206-b4', 'build207-b4',
           'build208-b4', 'build209-b4', 'build210-b4', 'build211-b4',
           'build212-b4', 'build213-b4', 'build214-b4', 'build215-b4',
           'build216-b4', 'build217-b4', 'build218-b4', 'build219-b4',
           'build220-b4', 'build221-b4']
      }
    ])
  waterfall = add_tester(
    waterfall, 'Win 10 4 Core Low-End Perf Tests',
    'win-10-4-core-low-end', 'win',
    swarming=[
      {
       'gpu': '8086:22b1',
       'os': 'Windows-10-10586',
       'device_ids': ['build47-b4', 'build48-b4'],
       'perf_tests': [
         ('cc_perftests', 0),
         ('gpu_perftests', 0),
         ('load_library_perf_tests', 0),
         ('angle_perftests', 1),
         ('performance_browser_tests', 1),
         ('tracing_perftests', 1)]
      }
    ],
    use_whitelist=True)
  return waterfall


def get_waterfall_config():
  waterfall = {'builders':[], 'testers': {}}

  # These configurations are taken from chromium_perf.py in
  # build/scripts/slave/recipe_modules/chromium_tests and must be kept in sync
  # to generate the correct json for each tester
  waterfall = add_tester(
    waterfall, 'Android Nexus5 Perf', 'android-nexus5',
    'android', target_bits=32, num_device_shards=7, num_host_shards=3)
  waterfall = add_tester(
    waterfall, 'Android Nexus5X Perf', 'android-nexus5X',
    'android', target_bits=32, num_device_shards=7, num_host_shards=3)
  waterfall = add_tester(
    waterfall, 'Android Nexus6 Perf', 'android-nexus6',
    'android', target_bits=32, num_device_shards=7, num_host_shards=3)
  waterfall = add_tester(
    waterfall, 'Android Nexus7v2 Perf', 'android-nexus7v2',
   'android', target_bits=32, num_device_shards=7, num_host_shards=3)
  waterfall = add_tester(
    waterfall, 'Android Nexus9 Perf', 'android-nexus9',
    'android', num_device_shards=7, num_host_shards=3)
  waterfall = add_tester(
    waterfall, 'Android One Perf', 'android-one',
    'android', target_bits=32, num_device_shards=7, num_host_shards=3)

  waterfall = add_tester(
    waterfall, 'Win Zenbook Perf', 'win-zenbook', 'win', num_host_shards=5)
  waterfall = add_tester(
    waterfall, 'Win 10 Perf', 'chromium-rel-win10', 'win', num_host_shards=5)
  waterfall = add_tester(
    waterfall, 'Win 8 Perf', 'chromium-rel-win8-dual', 'win', num_host_shards=5)
  waterfall = add_tester(
    waterfall, 'Win 7 Perf', 'chromium-rel-win7-dual',
    'win', target_bits=32, num_host_shards=5)
  waterfall = add_tester(
    waterfall, 'Win 7 x64 Perf',
    'chromium-rel-win7-x64-dual', 'win', num_host_shards=5)
  waterfall = add_tester(
    waterfall, 'Win 7 ATI GPU Perf',
    'chromium-rel-win7-gpu-ati', 'win', num_host_shards=5)
  waterfall = add_tester(
    waterfall, 'Win 7 Intel GPU Perf',
    'chromium-rel-win7-gpu-intel', 'win', num_host_shards=5)
  waterfall = add_tester(
    waterfall, 'Win 7 Nvidia GPU Perf',
    'chromium-rel-win7-gpu-nvidia', 'win', num_host_shards=5)

  waterfall = add_tester(
    waterfall, 'Mac 10.11 Perf', 'chromium-rel-mac11',
    'mac', num_host_shards=5)
  waterfall = add_tester(
    waterfall, 'Mac 10.10 Perf', 'chromium-rel-mac10',
    'mac',
    swarming=[
      {
       'os': 'Mac-10.10',
       'gpu': '8086:0a2e',
       'device_ids': [
           'build158-m1', 'build159-m1', 'build160-m1',
           'build161-m1', 'build162-m1']
      }
    ])
  waterfall = add_tester(
    waterfall, 'Mac Retina Perf',
    'chromium-rel-mac-retina', 'mac', num_host_shards=5)
  waterfall = add_tester(
    waterfall, 'Mac HDD Perf', 'chromium-rel-mac-hdd', 'mac', num_host_shards=5)
  waterfall = add_tester(
    waterfall, 'Mac Pro 10.11 Perf',
    'chromium-rel-mac11-pro', 'mac',
    swarming=[
      {
       'gpu': '1002:6821',
       'os': 'Mac-10.11',
       'device_ids': [
           'build128-b1', 'build129-b1',
           'build130-b1', 'build131-b1', 'build132-b1'
          ]
      }
    ])
  waterfall = add_tester(
    waterfall, 'Mac Air 10.11 Perf',
    'chromium-rel-mac11-air', 'mac',
    swarming=[
      {
       'gpu': '8086:1626',
       'os': 'Mac-10.11',
       'device_ids': [
           'build123-b1', 'build124-b1',
           'build125-b1', 'build126-b1', 'build127-b1'
          ]
      }
    ])

  waterfall = add_tester(
    waterfall, 'Linux Perf', 'linux-release', 'linux', num_host_shards=5)

  return waterfall


def generate_isolate_script_entry(swarming_dimensions, test_args,
  isolate_name, step_name, override_compile_targets=None):
  result = {
    'args': test_args,
    'isolate_name': isolate_name,
    'name': step_name,
  }
  if override_compile_targets:
    result['override_compile_targets'] = override_compile_targets
  if swarming_dimensions:
    result['swarming'] = {
      # Always say this is true regardless of whether the tester
      # supports swarming. It doesn't hurt.
      'can_use_on_swarming_builders': True,
      'expiration': 21600,
      'hard_timeout': 7200,
      'dimension_sets': swarming_dimensions,
    }
  return result


def generate_telemetry_test(swarming_dimensions, benchmark_name, browser):
  # The step name must end in 'test' or 'tests' in order for the
  # results to automatically show up on the flakiness dashboard.
  # (At least, this was true some time ago.) Continue to use this
  # naming convention for the time being to minimize changes.

  test_args = [
    benchmark_name,
    '-v',
    '--upload-results',
    '--output-format=chartjson',
    '--browser=%s' % browser
  ]
  # When this is enabled on more than just windows machines we will need
  # --device=android

  step_name = benchmark_name
  if browser == 'reference':
    test_args.append('--output-trace-tag=_ref')
    step_name += '.reference'

  return generate_isolate_script_entry(
    swarming_dimensions, test_args, 'telemetry_perf_tests',
    step_name, ['telemetry_perf_tests'])


def script_test_enabled_on_tester(master, test, tester_name, shard):
  for enabled_tester in test['testers'].get(master, []):
    if enabled_tester['name'] == tester_name:
      if shard in enabled_tester['shards']:
        return True
  return False


def generate_script_tests(master, tester_name, shard):
  script_tests = []
  for test in SCRIPT_TESTS:
    if script_test_enabled_on_tester(master, test, tester_name, shard):
      script = {
        'args': test['args'],
        'name': test['name'],
        'script': test['script']
      }
      script_tests.append(script)
  return script_tests


def get_swarming_dimension(dimension, device_affinity):
  complete_dimension = {
    'id': dimension['device_ids'][device_affinity],
    'os': dimension['os'],
    'pool': 'Chrome-perf',
  }
  if 'gpu' in dimension:
    complete_dimension['gpu'] = dimension['gpu']
  return complete_dimension


def generate_cplusplus_isolate_script_test(dimension):
  return [
    generate_isolate_script_entry(
        [get_swarming_dimension(dimension, shard)], [], name, name)
    for name, shard in dimension['perf_tests']
  ]


def generate_telemetry_tests(
  tester_config, benchmarks, benchmark_sharding_map, use_whitelist):
  isolated_scripts = []
  # First determine the browser that you need based on the tester
  browser_name = ''
  if tester_config['platform'] == 'android':
    browser_name = 'android-chromium'
  elif (tester_config['platform'] == 'win'
    and tester_config['target_bits'] == 64):
    browser_name = 'release_x64'
  else:
    browser_name ='release'

  num_shards = len(tester_config['swarming_dimensions'][0]['device_ids'])
  current_shard = 0
  for benchmark in benchmarks:
    # First figure out swarming dimensions this test needs to be triggered on.
    # For each set of dimensions it is only triggered on one of the devices
    swarming_dimensions = []
    for dimension in tester_config['swarming_dimensions']:
      sharding_map = benchmark_sharding_map.get(str(num_shards), None)
      if not sharding_map and not use_whitelist:
        raise Exception('Invalid number of shards, generate new sharding map')
      device_affinity = None
      if use_whitelist:
        device_affinity = current_shard
      else:
        device_affinity = sharding_map.get(benchmark.Name(), None)
      if device_affinity is None:
        raise Exception('Device affinity for benchmark %s not found'
          % benchmark.Name())
      swarming_dimensions.append(
          get_swarming_dimension(dimension, device_affinity))

    test = generate_telemetry_test(
      swarming_dimensions, benchmark.Name(), browser_name)
    isolated_scripts.append(test)
    # Now create another executable for this benchmark on the reference browser
    reference_test = generate_telemetry_test(
      swarming_dimensions, benchmark.Name(),'reference')
    isolated_scripts.append(reference_test)
    if current_shard == (num_shards - 1):
      current_shard = 0
    else:
      current_shard += 1

  return isolated_scripts


BENCHMARK_NAME_WHITELIST = set([
    u'smoothness.top_25_smooth',
    u'sunspider',
    u'system_health.webview_startup',
    u'page_cycler_v2.intl_hi_ru',
    u'dromaeo.cssqueryjquery',
])

# List of benchmarks that are to never be run on a waterfall.
BENCHMARK_NAME_BLACKLIST = [
    'multipage_skpicture_printer',
    'multipage_skpicture_printer_ct',
    'rasterize_and_record_micro_ct',
    'repaint_ct',
    'multipage_skpicture_printer',
    'multipage_skpicture_printer_ct',
    'skpicture_printer',
    'skpicture_printer_ct',
]


def current_benchmarks(use_whitelist):
  current_dir = os.path.dirname(__file__)
  benchmarks_dir = os.path.join(current_dir, 'benchmarks')
  top_level_dir = os.path.dirname(benchmarks_dir)

  all_benchmarks = discover.DiscoverClasses(
      benchmarks_dir, top_level_dir, benchmark_module.Benchmark,
      index_by_class_name=True).values()
  # Remove all blacklisted benchmarks
  for blacklisted in BENCHMARK_NAME_BLACKLIST:
    for benchmark in all_benchmarks:
      if benchmark.Name() == blacklisted:
        all_benchmarks.remove(benchmark)
        break

  if use_whitelist:
    all_benchmarks = (
        bench for bench in all_benchmarks
        if bench.Name() in BENCHMARK_NAME_WHITELIST)
  return sorted(all_benchmarks, key=lambda b: b.Name())


# Returns a sorted list of (benchmark, avg_runtime) pairs for every
# benchmark in the all_benchmarks list where avg_runtime is in seconds.  Also
# returns a list of benchmarks whose run time have not been seen before
def get_sorted_benchmark_list_by_time(all_benchmarks):
  runtime_list = []
  benchmark_avgs = {}
  new_benchmarks = []
  # Load in the avg times as calculated on Nov 1st, 2016
  with open('desktop_benchmark_avg_times.json') as f:
    benchmark_avgs = json.load(f)

  for benchmark in all_benchmarks:
    benchmark_avg_time = benchmark_avgs.get(benchmark.Name(), None)
    if benchmark_avg_time is None:
      # Assume that this is a new benchmark that was added after 11/1/16 when
      # we generated the benchmarks. Use the old affinity algorith after
      # we have given the rest the same distribution, add it to the
      # new benchmarks list.
      print ('Warning: Benchmark %s was not seen in times generated on Nov1 '
        '2016, defaulting to old device affinity algorithm' % benchmark.Name())
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


def generate_all_tests(waterfall):
  tests = {}
  for builder in waterfall['builders']:
    tests[builder] = {}
  all_benchmarks = current_benchmarks(False)
  whitelist_benchmarks = current_benchmarks(True)
  # Get benchmark sharding according to common sharding configurations
  # Currently we only have bots sharded 5 directions and 1 direction
  benchmark_sharding_map = {}
  benchmark_sharding_map['22'] = shard_benchmarks(22, all_benchmarks)
  benchmark_sharding_map['5'] = shard_benchmarks(5, all_benchmarks)
  benchmark_sharding_map['1'] = shard_benchmarks(1, all_benchmarks)

  for name, config in waterfall['testers'].iteritems():
    use_whitelist = config['use_whitelist']
    benchmark_list = all_benchmarks
    if use_whitelist:
      benchmark_list = whitelist_benchmarks
    if config.get('swarming', False):
      # Our current configuration only ever has one set of swarming dimensions
      # Make sure this still holds true
      if len(config['swarming_dimensions']) > 1:
        raise Exception('Invalid assumption on number of swarming dimensions')
      # Generate benchmarks
      isolated_scripts = generate_telemetry_tests(
          config, benchmark_list, benchmark_sharding_map, use_whitelist)
      # Generate swarmed non-telemetry tests if present
      if config['swarming_dimensions'][0].get('perf_tests', False):
        isolated_scripts += generate_cplusplus_isolate_script_test(
          config['swarming_dimensions'][0])
      tests[name] = {
        'isolated_scripts': sorted(isolated_scripts, key=lambda x: x['name'])
      }
    else:
      # scripts are only currently run in addition to the main waterfall.  They
      # are currently the only thing generated in the perf json file.
      # TODO eyaich: will need to handle the sharding differently when we have
      # swarmed bots on the main waterfall.
      for shard in range(0, config['num_host_shards']):
        tester_name = '%s (%d)' % (name, shard + 1)
        scripts = generate_script_tests(waterfall['name'], name, shard + 1)
        if scripts:
          tests[tester_name] = {
            'scripts': sorted(scripts, key=lambda x: x['name'])
          }

  tests['AAAAA1 AUTOGENERATED FILE DO NOT EDIT'] = {}
  tests['AAAAA2 See //tools/perf/generate_perf_json.py to make changes'] = {}
  filename = '%s.json' % waterfall['name']

  current_dir = os.path.dirname(os.path.abspath(__file__))
  src_dir = os.path.dirname(os.path.dirname(current_dir))

  with open(os.path.join(src_dir, 'testing', 'buildbot', filename), 'w') as fp:
    json.dump(tests, fp, indent=2, separators=(',', ': '), sort_keys=True)
    fp.write('\n')


def main():
  waterfall = get_waterfall_config()
  waterfall['name'] = 'chromium.perf'
  fyi_waterfall = get_fyi_waterfall_config()
  fyi_waterfall['name'] = 'chromium.perf.fyi'

  generate_all_tests(fyi_waterfall)
  generate_all_tests(waterfall)
  return 0

if __name__ == '__main__':
  sys.exit(main())
