# Android code coverage instructions

This is instruction for code coverage for android instrumentation and junit tests.

[TOC]

## How EMMA coverage works

In order to use EMMA code coverage, we need to create build time **.em** file and runtime
**.ec** file. Then we need to process them using the
build/android/generate_emma_html.py script.

## How to collect EMMA coverage data

1. Build your APK with the GN arg emma_coverage=true.
   ```
   gn args out-gn/Debug
   > target_os = "android"
   > emma_coverage = true
   ```
   By doing so, **.em** files will be created in out-gn/Debug.
2. Run tests, with option `--coverage-dir <directory>`, to specify where to save
   the .ec file. For example, you can run chrome junit tests:
   `out-gn/Debug/bin/run_chrome_junit_tests --coverage-dir /tmp/coverage`.
3. Now we have both .em and .ec files. We can merge them and create a html file,
   using generate_emma_html.py. For example, generate_emma_html.py can be called
   this way:
   `build/android/generate_emma_html.py --coverage-dir /tmp/coverage/
   --metadata-dir out-gn/Debug/ --output example.html`.
   Then an example.html containing coverage info will be created:
   `EMMA: writing [html] report to
   [<your_current_directory>/example.html] …`
