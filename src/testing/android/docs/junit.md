# JUnit Tests

JUnit tests are Java unit tests. These tests run locally on your workstation.

[TOC]

## Writing a JUnit test

When writing JUnit tests, you must decide whether you need to use Android code.
If you want to use Android code you must write a [Robolectric](http://robolectric.org/) test.

### JUnit tests (without Android)

Build these types of test using the `junit_binary` GN template.

If you don't need to use any Android code in your tests, you can write plain,
old JUnit tests. Some more documentation about writing JUnit tests can be
found [here](https://github.com/junit-team/junit4/wiki/Getting-started).

#### Example Code

```java
package org.chromium.sample.test;

import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.BlockJUnit4ClassRunner;

@RunWith(BlockJUnit4ClassRunner.class)
public class MyJUnitTest {

    @Test
    public void exampleTest() {
        boolean shouldWriteMoreJUnitTests = true;
        assertTrue(shouldWriteMoreJUnitTests);
    }
}
```

#### Example within Chromium

See the [junit_unit_tests](https://cs.chromium.org/chromium/src/testing/android/junit/BUILD.gn) test suite.

### JUnit tests with Robolectric

Build these types of test using the `junit_binary` GN template.

Robolectric is a unit testing framework that lets you run tests with Android
code on your workstation. It does this by providing a special version of the
Android SDK jar that can run in your host JVM. Some more information about
Robolectric can be found [here](http://robolectric.org/).

#### Useful Tips

* Use `@RunWith(LocalRobolectricTestRunner.class)` for all Chromium Robolectric tests.
* Use `@Config(manifest = Config.NONE)` for tests.
  Currently, you are unable to pass your app's AndroidManifest to Robolectric.
* You can specify the Android SDK to run your test with with `@Config(sdk = ??)`.

> Currently, only SDK levels 18, 21, and 25 are supported in Chromium
> but more can be added on request.

#### Example Code

```java
package org.chromium.sample.test;

import static org.junit.Assert.assertTrue;

import android.text.TextUtils;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.annotation.Config;

import org.chromium.testing.local.LocalRobolectricTestRunner;

// Be sure to specify to run tests with the LocalRobolectricTestRunner. The
// default JUnit test runner won't load the Robolectric Android code properly.
@RunWith(LocalRobolectricTestRunner.class)
// Can specify some Robolectric related configs here.
// More about configuring Robolectric at http://robolectric.org/configuring/.
// SDK will default to the latest we support in Chromium.
@Config(manifest = Config.NONE, sdk = 21)
public class MyRobolectricJUnitTest {

    @Test
    public void exampleTest() {
        String testString = "test";

        // Even though these tests runs on the host, Android classes are
        // available to use thanks to Robolectric.
        assertTrue(TextUtils.equals(testString, "test"));
    }
}
```

#### Example within Chromium

See the [content_junit_tests](https://cs.chromium.org/chromium/src/content/public/android/BUILD.gn) test suite.

## Running JUnit tests

After writing a test, you can run it by:

1. Adding the test file to a `junit_binary` GN target.
2. Rebuild.
3. GN will generate binary `<out_dir>/bin/run_<suite name>` which
   can be used to run your test.

For example, the following can be used to run chrome_junit_tests.

```bash
# Build the test suite after adding our new test.
ninja -C out/Debug chrome_junit_tests

# Run the test!
out/Debug/bin/run_chrome_junit_tests
```