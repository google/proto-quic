# How to Deal with Android Size Alerts

*Not all alerts should not have a bug created for them. Please read on...*

### If the alert is for "other lib size" or "Unknown files size":
 * File a bug against agrieve@ to fix
   [resource_sizes.py](https://cs.chromium.org/chromium/src/build/android/resource_sizes.py).
 * ...or fix it yourself. This script will output the list of unknown
   filenames.

### If the alert is a downstream size alert (aka, for Monochrome.apk):
 * The regression most likely already occurred in the upstream
   MonochromePublic.apk target. Look at the
   [upstream graphs](https://chromeperf.appspot.com/report?sid=cfc29eed1238fd38fb5e6cf83bdba6c619be621b606e03e5dfc2e99db14c418b&num_points=1500)
   to find the culprit & de-dupe with upstream alerts.
 * If no upstream regression was found, look through the downstream commits
   within the given date range to find the culprit.
    * Via `git log --format=fuller` (be sure to look at `CommitDate` and not
      `AuthorDate`)

### If the alert is for a roll, or has multiple commits listed:
 * Use a bisect to try and determine a more precise commit.
    * Except don't. Bisects for these alerts [are currently broken](https://bugs.chromium.org/p/chromium/issues/detail?id=678338).
    * Until this is fixed, just file a bug and assign to agrieve@.

### What to do once the commit is identified:
 * If the code seems to justify the size increase:
    1. Annotate the code review with the following (replacing **bold** parts):
       > FYI - this added **20kb** to Chrome on Android. No action is required
       > (unless you can think of an obvious way to reduce the overhead).
       >
       > Link to size graph:
[https://chromeperf.appspot.com/report?sid=cfc29eed1238fd38fb5e6cf83bdba6c619be621b606e03e5dfc2e99db14c418b&rev=**440074**](https://chromeperf.appspot.com/report?sid=cfc29eed1238fd38fb5e6cf83bdba6c619be621b606e03e5dfc2e99db14c418b&rev=440074)
    2. Add an entry to
      [this spreadsheet](https://docs.google.com/spreadsheets/d/1GrRkszV7Oy5pVsaMb5Eb6s8izW9t4dElBxIH3iGq93o/edit#gid=1894856744)
      to document the increase (also Update the "Themes / Thoughts" tab if
      applicable).
 * If the code might not justify the size increase:
    1. File a bug and assign to the author to follow-up.
        * Change the bug's title from X% to XXkb
        * Paste in link to commit or review URL that is at fault.
        * Paste in link to [https://chromium.googlesource.com/chromium/src/+/master/tools/perf/docs/apk_size_regressions.md#Debugging-Apk-Size-Increase](https://chromium.googlesource.com/chromium/src/+/master/tools/perf/docs/apk_size_regressions.md#Debugging-Apk-Size-Increase).
        * Remove label: `Restrict-View-Google`
        * Add label: `binary-size`
        * TODO(agrieve): [https://github.com/catapult-project/catapult/issues/3150](Change bug template to match these instructions)
    2. Add an entry to
      [this spreadsheet](https://docs.google.com/spreadsheets/d/1GrRkszV7Oy5pVsaMb5Eb6s8izW9t4dElBxIH3iGq93o/edit#gid=1894856744)
      to document the increase.

# Debugging Apk Size Increase

## Step 1: Identify where the extra bytes came from

Figure out which file within the .apk increased by looking at the size graphs
showing the breakdowns.

 * Refer to the chromeperf link that should have been posted to your code
   review (see above).
 * Alternatively, refer to "Apk Size" section here:
   [https://goto.google.com/clank/dashboards](https://goto.google.com/clank/dashboards) (*googler only*).

## Step 2: Reproduce build results locally

### Option 1: Build Locally
 1. Follow the normal [Android build instructions](https://chromium.googlesource.com/chromium/src/+/master/docs/android_build_instructions.md).
 1. Ensure you're using the same GN args as the bots by looking at the `generate_build_files` step of the build:
    * https://luci-logdog.appspot.com/v/?s=chrome%2Fbb%2Fchromium.perf%2FAndroid_Builder%2F**134505**%2F%2B%2Frecipes%2Fsteps%2Fgenerate_build_files%2F0%2Fstdout
 3. Save artifacts you'll need for diffing:

```shell
    mv out/Release/lib.unstripped out/Release/lib.unstripped.withchange
    mv out/Release/apks out/Release/apks.withchange
```

### Option 2: Download artifacts from perf jobs (Googlers only)**
 1. Replace the bolded part of the following URL with the git commit hash:
  [https://storage.cloud.google.com/chrome-perf/Android%20Builder/full-build-linux_**HASH**.zip](https://storage.cloud.google.com/chrome-perf/Android%20Builder/full-build-linux_**HASH**.zip)

## Step 3: Analyze

 * If the growth is from native code:
    * Refer to techniques used in [crbug.com/681991](https://bugs.chromium.org/p/chromium/issues/detail?id=681991)
      and [crbug.com/680973](https://bugs.chromium.org/p/chromium/issues/detail?id=680973).
 * If the growth is from java code:
    * Use [tools/android/dexdiffer/dexdiffer.py](https://cs.chromium.org/chromium/src/tools/android/dexdiffer/dexdiffer.py).
        * This currently just shows a list of symbols added / removed rather than
          taking into account method body sizes.
        * Enhancements to this tool tracked at
          [crbug/678044](https://bugs.chromium.org/p/chromium/issues/detail?id=678044).
 * If the growth is from images, ensure they are optimized:
    * Would it be smaller as a VectorDrawable?
    * If it's lossy, consider using webp.
    * Ensure you've optimized with
      [tools/resources/optimize-png-files.sh](https://cs.chromium.org/chromium/src/tools/resources/optimize-png-files.sh).
    * There is some [Googler-specific guidance](https://goto.google.com/clank/engineering/best-practices/adding-image-assets) as well.
