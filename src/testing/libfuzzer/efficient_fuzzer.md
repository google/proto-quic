# Efficient Fuzzer

This document describes ways to determine your fuzzer efficiency and ways 
to improve it.

## Overview

Being a coverage-driven fuzzer, libFuzzer considers a certain input *interesting*
if it results in new coverage. The set of all interesting inputs is called 
*corpus*. 
Items in corpus are constantly mutated in search of new interesting input.
Corpus is usually maintained between multiple fuzzer runs.

Following things can be so effective for a fuzzer, that we *strongly recommend*
for any fuzzer:

* [seed corpus](#Seed-Corpus) gives your fuzzer examples of input.
* [fuzzer dictionary](#Fuzzer-Dictionary) improves fuzzer mutations by using
  supplied dictionary.

There are several metrics you should look at to determine your fuzzer effectiveness:

* [fuzzer speed](#Fuzzer-Speed) (exec/s)
* [corpus size](#Corpus-Size)
* [coverage](#Coverage)

You can collect these metrics manually or take them from [ClusterFuzz status]
pages.

## Seed Corpus

You can pass a corpus directory to a fuzzer that you run manually:

```
./out/libfuzzer/my_fuzzer ~/tmp/my_fuzzer_corpus
```

The directory can initially be empty. The fuzzer would store all the interesting
items it finds in the directory. You can help the fuzzer by "seeding" the corpus:
simply copy interesting inputs for your function to the corpus directory before
running. This works especially well for strictly defined file formats or data
transmission protocols.

* For file-parsing functionality just use some valid files from your test suite.

* For protocol processing targets put raw streams from test suite into separate
files.


ClusterFuzz uses seed corpus stored in Chromium repository. You need to add
`seed_corpus` attribute to fuzzer target:

```
fuzzer_test("my_protocol_fuzzer") {
  ...
  seed_corpus = "src/fuzz/testcases"
  ...
}
```

You may specify multiple seed corpus directories via `seed_corpuses` attribute:

```
fuzzer_test("my_protocol_fuzzer") {
  ...
  seed_corpuses = [ "src/fuzz/testcases", "src/unittest/data" ]
  ...
}
```

All files found in the directories and their subdirectories will be archived
into `%YOUR_FUZZER_NAME%_seed_corpus.zip` output archive.

If you don't want to store seed corpus in Chromium repository, you can upload
corpus to Google Cloud Storage bucket used by ClusterFuzz:


1) go to [Corpus GCS Bucket]

2) open directory named `%YOUR_FUZZER_NAME%_static`

3) upload corpus files into the directory


Alternative way is to use `gsutil` tool:
```bash
gsutil -m rsync <corpus_dir_on_disk> gs://clusterfuzz-corpus/libfuzzer/%YOUR_FUZZER_NAME%_static
```

## Fuzzer Dictionary

It is very useful to provide fuzzer a set of common words/values that you expect
to find in the input. This greatly improves efficiency of finding new units and
works especially well while fuzzing file format decoders.

To add a dictionary, first create a dictionary file.
Dictionary syntax is similar to that used by [AFL] for its -x option:

```
# Lines starting with '#' and empty lines are ignored.

# Adds "blah" (w/o quotes) to the dictionary.
kw1="blah"
# Use \\ for backslash and \" for quotes.
kw2="\"ac\\dc\""
# Use \xAB for hex values
kw3="\xF7\xF8"
# the name of the keyword followed by '=' may be omitted:
"foo\x0Abar"
```

Test your dictionary by running your fuzzer locally:

```bash
./out/libfuzzer/my_protocol_fuzzer -dict=<path_to_dict> <path_to_corpus>
```

You should see lots of new units discovered.

Add `dict` attribute to fuzzer target:

```
fuzzer_test("my_protocol_fuzzer") {
  ...
  dict = "protocol.dict"
}
```

Make sure to submit dictionary file to git. The dictionary will be used
automatically by ClusterFuzz once it picks up new fuzzer version (once a day).

## Fuzzer Speed

Fuzzer speed is printed while fuzzer runs:

```
#19346  NEW    cov: 2815 bits: 1082 indir: 43 units: 150 exec/s: 19346 L: 62
```

Because libFuzzer performs randomized search, it is critical to have it as fast
as possible. You should try to get to at least 1,000 exec/s. Profile the fuzzer
using any standard tool to see where it spends its time.


### Initialization/Cleanup

Try to keep your fuzzing function as simple as possible. Prefer to use static
initialization and shared resources rather than bringing environment up and down
every single run.

Fuzzers don't have to shutdown gracefully (we either kill them or they crash
because sanitizer has found a problem). You can skip freeing static resource.

Of course all resources allocated within `LLVMFuzzerTestOneInput` function
should be deallocated since this function is called millions of times during
one fuzzing session.


### Memory Usage

Avoid allocation of dynamic memory wherever possible. Instrumentation works
faster for stack-based and static objects than for heap allocated ones.

It is always a good idea to play with different versions of a fuzzer to find the
fastest implementation.


### Maximum Testcase Length

Experiment with different values of `-max_len` parameter. This parameter often
significantly affects execution speed, but not always.

1) Define which `-max_len` value is reasonable for your target. For example, it
may be useless to fuzz an image decoder with too small value of testcase length.

2) Increase the value defined on previous step. Check its influence on execution
speed of fuzzer. If speed doesn't drop significantly for long inputs, it is fine
to have some bigger value for `-max_len`.

In general, bigger `-max_len` value gives better coverage. Coverage is main
priority for fuzzing. However, low execution speed may result in waste of
resources used for fuzzing. If large inputs make fuzzer too slow you have to
adjust value of `-max_len` and find a trade-off between coverage and execution
speed.

*Note:* ClusterFuzz runs two different fuzzing engines (**LibFuzzer** and
**AFL**) using the same target functions. AFL doesn't support `-max_len`
parameter and may provide input of any length to the target. If your target has
an input length limit that you would like to *strictly enforce*, it's
recommended to add a sanity check to the beginning of your target function:

```
if (size > kSizeLimit)
  return 0;
```

For more information check out the discussion in [issue 638836].


## Coverage

[ClusterFuzz status] page provides fuzzer source-level coverage report 
from the recent run. Looking at the report might provide an insight
to improve fuzzer coverage.

You can also access source-level coverage report locally:

```bash
# produces binary .sancov file
ASAN_OPTIONS=coverage=1 ./out/libfuzzer/my_fuzzer -runs=0 ~/tmp/my_fuzzer_corpus
# Convert binary .sancov to symbolized .symcov file.
./third_party/llvm-build/Release+Asserts/bin/sancov \
  -symbolize my_fuzzer my_fuzzer.123.sancov > my_fuzzer.symcov
# Launch coverage report server
curl https://llvm.org/svn/llvm-project/llvm/trunk/tools/sancov/coverage-report-server.py | python3 \
  --symcov my_fuzzer.symcov --srcpath path_to_chromium_sources
# Navigate to http://localhost:8001/ to view coverage report
```
Replace `ASAN_OPTIONS` by corresponding option variable if your are using 
another sanitizer (e.g. `MSAN_OPTIONS`).

*NOTE: This is an experimental feature and an active area of work. We are 
working on improving this process.*


## Corpus Size

After running for a while the fuzzer would reach a plateau and won't discover
new interesting input. Corpus for a reasonably complex functionality
should contain hundreds (if not thousands) of items.

Too small corpus size indicates some code barrier that
libFuzzer is having problems penetrating. Common cases include: checksums,
magic numbers etc. The easiest way to diagnose this problem is to generate a 
[coverage report](#Coverage). To fix the issue you can:

* change the code (e.g. disable crc checks while fuzzing)
* prepare [corpus seed](#Corpus-Seed)
* prepare [fuzzer dictionary](#Fuzzer-Dictionary)
* specify [custom options](#Custom-Options)

### Custom Options

It is possible to specify [libFuzzer parameters](http://llvm.org/docs/LibFuzzer.html#usage)
for any fuzzer being run at ClusterFuzz. Custom options will overwrite default
values provided by ClusterFuzz.

Just list all parameters in `libfuzzer_options` variable of build target:

```
fuzzer_test("my_protocol_fuzzer") {
  ...
  libfuzzer_options = [
    "max_len=2048",
    "use_traces=1",
  ]
}
```

Please note that `dict` parameter should be provided [separately](#Fuzzer-Dictionary).
Other options may be passed through `libfuzzer_options` property.


[AFL]: http://lcamtuf.coredump.cx/afl/
[ClusterFuzz status]: clusterfuzz.md#Status-Links
[Corpus GCS Bucket]: https://goto.google.com/libfuzzer-clusterfuzz-corpus
[issue 638836]: https://bugs.chromium.org/p/chromium/issues/detail?id=638836
