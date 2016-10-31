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
          'name': 'Android Galaxy S5 Perf',
          'shards': [3]
        },
        {
          'name': 'Android Nexus5 Perf',
          'shards': [2]
        },
        {
          'name': 'Android Nexus7v2 Perf',
          'shards': [2]
        },
        {
          'name': 'Android Nexus9 Perf',
          'shards': [2]
        }
      ],
      'chromium.perf.fyi': [
        {
          'name': 'Android Galaxy S5 Perf',
          'shards': [1]
        },
      ]
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
          'name': 'Android Galaxy S5 Perf',
          'shards': [3]
        },
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
      'chromium.perf.fyi': [
        {
          'name': 'Android Galaxy S5 Perf',
          'shards': [1]
        },
      ]
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
              num_host_shards=1, num_device_shards=1, swarming=None):
  del perf_id # this will be needed
  waterfall['testers'][name] = {
    'platform': platform,
    'num_device_shards': num_device_shards,
    'num_host_shards': num_host_shards,
    'target_bits': target_bits,
  }

  if swarming:
    waterfall['testers'][name]['swarming_dimensions'] = swarming
    waterfall['testers'][name]['swarming'] = True

  return waterfall

def get_fyi_waterfall_config():
  waterfall = {'builders':[], 'testers': {}}
  waterfall = add_tester(
    waterfall, 'Android Galaxy S5 Perf',
    'android-galaxy-s5-perf', 'android')
  waterfall = add_tester(
    waterfall, 'Win 10 Low-End Perf Tests',
    'win-low-end-2-core', 'win',
    swarming=[
      {
       'gpu': '1002:9874',
       'os': 'Windows-10-10586',
       'device_ids': ['build171-b4', 'build186-b4']
      }
    ])
  return waterfall

def get_waterfall_config():
  waterfall = {'builders':[], 'testers': {}}

  # These configurations are taken from chromium_perf.py in
  # build/scripts/slave/recipe_modules/chromium_tests and must be kept in sync
  # to generate the correct json for each tester
  waterfall = add_tester(
    waterfall, 'Android Galaxy S5 Perf',
    'android-galaxy-s5', 'android', target_bits=32,
    num_device_shards=7, num_host_shards=3)
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
    'mac', num_host_shards=5)
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

  swarming = None
  if swarming_dimensions:
    swarming = {
      # Always say this is true regardless of whether the tester
      # supports swarming. It doesn't hurt.
      'can_use_on_swarming_builders': True,
      'expiration': 14400,
      'dimension_sets': swarming_dimensions
    }

  result = {
    'args': test_args,
    'isolate_name': 'telemetry_perf_tests',
    'name': step_name,
    'override_compile_targets': ['telemetry_perf_tests'],
  }
  if swarming:
    result['swarming'] = swarming

  return result

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

def generate_telemetry_tests(tester_config, benchmarks):
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

  for benchmark in benchmarks:
    # First figure out swarming dimensions this test needs to be triggered on.
    # For each set of dimensions it is only triggered on one of the devices
    swarming_dimensions = []
    for dimension in tester_config['swarming_dimensions']:
      device_affinity = bot_utils.GetDeviceAffinity(
          len(dimension['device_ids']), benchmark.Name())

      device_id = dimension['device_ids'][device_affinity]
      # Id is unique within the swarming pool so it is the only needed
      # identifier for the bot to run the test on
      swarming_dimensions.append({
        'id': device_id,
        'gpu': dimension['gpu'],
        'os': dimension['os'],
        'pool': 'Chrome-perf',
      })

    test = generate_telemetry_test(
      swarming_dimensions, benchmark.Name(), browser_name)
    isolated_scripts.append(test)
    # Now create another executable for this benchmark on the reference browser
    reference_test = generate_telemetry_test(
      swarming_dimensions, benchmark.Name(),'reference')
    isolated_scripts.append(reference_test)

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


def generate_all_tests(waterfall, use_whitelist):
  tests = {}
  for builder in waterfall['builders']:
    tests[builder] = {}
  all_benchmarks = current_benchmarks(use_whitelist)

  for name, config in waterfall['testers'].iteritems():
    if config.get('swarming', False):
      # Right now we are only generating benchmarks for the fyi waterfall
      isolated_scripts = generate_telemetry_tests(config, all_benchmarks)
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

  generate_all_tests(fyi_waterfall, True)
  generate_all_tests(waterfall, False)
  return 0

if __name__ == "__main__":
  sys.exit(main())
