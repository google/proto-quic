# Reproducing ClusterFuzz bugs locally

ClusterFuzz will report bugs in the bug tracker in the following form:

```
Detailed report: https://cluster-fuzz.appspot.com/testcase?key=...

Fuzzer: libfuzzer_media_pipeline_integration_fuzzer
Job Type: libfuzzer_chrome_asan
Platform Id: linux

Crash Type: Heap-buffer-overflow READ {*}
Crash Address: 0x60500000c64d
Crash State:
  stack_frame1
  stack_frame2
  stack_frame3

Recommended Security Severity: Medium

Regressed: <LINK>

Minimized Testcase (6.86 Kb): <LINK>

Filer: ...
```

You can click the "Detailed report" link for the full stack trace, and
additional information/links.

## Steps to reproduce

1. Download the testcase given by the "Minimized Testcase" link.

2. (**Important**) In the following sections, `$FUZZER_NAME` will be the the
   string specified after the "Fuzzer :" in the report, but *without* the
   "libfuzzer_" or "afl_" prefix. In this case, the `$FUZZER_NAME` is
   "media_pipeline_integration_fuzzer".

3. Follow the steps in one of the subsequent sections (from a chromium
   checkout).  The string specified after the "Job Type: " will be either
   `afl_chrome_asan`, `libfuzzer_chrome_asan`, `libfuzzer_chrome_msan`, or
   `libfuzzer_chrome_ubsan`, indicating which one to use.


*Notes*:

* `is_debug`:  ClusterFuzz uses release builds by default (`is_debug=false`).
For ASan builds, both Debug and Release configurations are supported.
Check a job type of the report for presence of `_debug` suffix.

* `ffmpeg_branding`: For Linux `ffmpeg_branding` should be set to `ChromeOS`.
For other platforms, use `ffmpeg_branding=Chrome`.

### Reproducing AFL + ASan bugs
```bash
$ gn gen out/afl '--args=is_debug=false use_afl=true is_asan=true enable_nacl=false proprietary_codecs=true ffmpeg_branding="ChromeOS"'
$ ninja -C out/afl $FUZZER_NAME
$ out/afl/$FUZZER_NAME < /path/to/repro
```

### Reproducing LibFuzzer + ASan bugs

```bash
$ gn gen out/libfuzzer '--args=is_debug=false use_libfuzzer=true is_asan=true enable_nacl=false proprietary_codecs=true ffmpeg_branding="ChromeOS"'
$ ninja -C out/libfuzzer $FUZZER_NAME
$ out/libfuzzer/$FUZZER_NAME /path/to/repro
```

### Reproducing LibFuzzer + MSan bugs

```bash
# The gclient runhooks is necessary to pull in instrumented libraries.
$ GYP_DEFINES='msan=1 use_prebuilt_instrumented_libraries=1' gclient runhooks
$ gn gen out/libfuzzer '--args=is_debug=false use_libfuzzer=true is_msan=true msan_track_origins=2 use_prebuilt_instrumented_libraries=true enable_nacl=false proprietary_codecs=true ffmpeg_branding="ChromeOS"'
$ ninja -C out/libfuzzer $FUZZER_NAME
$ out/libfuzzer/$FUZZER_NAME /path/to/repro
```

### Reproducing LibFuzzer + UBSan bugs

```bash
$ gn gen out/libfuzzer '--args=is_debug=false use_libfuzzer=true is_ubsan_security=true enable_nacl=false proprietary_codecs=true ffmpeg_branding="ChromeOS"'
$ ninja -C out/libfuzzer $FUZZER_NAME
$ export UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
$ out/libfuzzer/$FUZZER_NAME /path/to/repro
```

### Symbolization

Memory tools (ASan, MSan, UBSan) use [llvm-symbolizer] binary from the Clang
distribution to symbolize the stack traces. To get a symbolized crash report,
make sure `llvm-symbolizer` is in `PATH` or provide it in separate
`ASAN_SYMBOLIZER_PATH` environment variable.

In Chromium repository `llvm-symbolizer` is located in
`third_party/llvm-build/Release+Asserts/bin` directory.

```bash
$ export ASAN_SYMBOLIZER_PATH=/path/to/chromium/src/third_party/llvm-build/Release+Asserts/bin/llvm-symbolizer
$ out/libfuzzer/$FUZZER_NAME /path/to/repro
```

The same approach works for `MSAN_SYMBOLIZER_PATH` and `UBSAN_SYMBOLIZER_PATH`.

Additional information regarding symbolization is available in sanitizers
documentation: [AddressSanitizerCallStack].


### Debugging

Please look at [AddressSanitizerAndDebugger] page for some tips on debugging of
binaries built with ASan.

If you want gdb to stop after an error has been reported, use:

* `ASAN_OPTIONS=abort_on_error=1` for binaries built with ASan.
* `MSAN_OPTIONS=abort_on_error=1` for binaries built with MSan.



[AddressSanitizerAndDebugger]: https://github.com/google/sanitizers/wiki/AddressSanitizerAndDebugger
[AddressSanitizerCallStack]: https://github.com/google/sanitizers/wiki/AddressSanitizerCallStack
[llvm-symbolizer]: http://llvm.org/docs/CommandGuide/llvm-symbolizer.html
