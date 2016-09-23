# libFuzzer Integration Reference

## Supported Platforms and Configurations

### Linux

Linux is fully supported by libFuzzer and ClusterFuzz with following sanitizer 
configurations:

| GN Argument | Description |
|--------------|----|
| is_asan=true | enables [Address Sanitizer] to catch problems like buffer overruns. |
| is_msan=true | enables [Memory Sanitizer] to catch problems like uninitialed reads. |
| is_ubsan_security=true | enables [Undefined Behavior Sanitizer] to catch<sup>\[[1](#Notes)\]</sup> undefined behavior like integer overflow. |

Configuration example:

```bash
# With address sanitizer
gn gen out/libfuzzer '--args=use_libfuzzer=true is_asan=true enable_nacl=false' --check
```

### Mac

Mac is experimentally supported by libFuzzer with `is_asan` configuration. Mac
support is not provided by ClusterFuzz.

Configuration example:

```bash
gn gen out/libfuzzer '--args=use_libfuzzer=true is_asan=true enable_nacl=false mac_deployment_target="10.7"' --check
```


## fuzzer_test GN Template

Use `fuzzer_test` to define libFuzzer targets:

```
fuzzer_test("my_fuzzer") {
  ...
}
```

Following arguments are supported:

| Argument | Description |
|----------|-------------|
| sources | **required** list of fuzzer test source files. |
| deps | fuzzer dependencies |
| additional_configs | additional GN configurations to be used for compilation |
| dict | a dictionary file for the fuzzer |
| libfuzzer_options | runtime options file for the fuzzer. See [Fuzzer Runtime Options](Fuzzer-Options) |


## Fuzzer Runtime Options

There are many different runtime options supported by libFuzzer. Options
are passed as command line arguments:

```
./fuzzer [-flag1=val1 [-flag2=val2 ...] ] [dir1 [dir2 ...] ]
```

Most common flags are:

| Flag | Description |
|------|-------------|
| max_len | Maximum length of test input. |
| timeout | Timeout of seconds. Units slower than this value will be reported as bugs. |

A fuller list of options can be found at [libFuzzer Usage] page and by running
the binary with `-help=1`.

To specify these options for ClusterFuzz, list all parameters in
`libfuzzer_options` target attribute:

```
fuzzer_test("my_fuzzer") {
  ...
  libfuzzer_options = [
    "max_len=2048",
    "use_traces=1",
  ]
}
```

[libFuzzer Usage]: http://llvm.org/docs/LibFuzzer.html#usage
[Address Sanitizer]: http://clang.llvm.org/docs/AddressSanitizer.html
[Memory Sanitizer]: http://clang.llvm.org/docs/MemorySanitizer.html
[Undefined Behavior Sanitizer]: http://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html

