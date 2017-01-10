# How to Deal with Apk Size Alerts

### If the alert is for "other lib size" or "Unknown files size":
 * File a bug against agrieve@ to fix
   [resource_sizes.py](https://cs.chromium.org/chromium/src/build/android/resource_sizes.py).
 * ...or fix it yourself. This script will output the list of unknown
   filenames.

### If the alert is a downstream size alert (aka, for Monochrome.apk):
 * The regression most likely already occurred in the upstream
   MonochromePublic.apk target. Look at the
   [upstream graphs](https://chromeperf.appspot.com/report?sid=5cfed2a07b55702fc64255a316cdb78531e916da4e933677645bbf1fe78cf2e0&num_points=1500)
   to find the culprit & de-dupe with upstream alerts.
 * If no upstream regression was found, look through the downstream commits
   within the given date range to find the culprit.
    * Via `git log --format=fuller` (be sure to look at `CommitDate` and not
      `AuthorDate`)

### If the alert is for a roll:
 * Use a bisect to try and determine a more precise commit.

### What to do once the commit is identified:
 * If the code seems to justify the size increase:
    1. Annotate the code review with the following (replacing **bold** parts):
       > FYI - this added **20kb** to Chrome on Android. No action is required
       > (unless you can think of an obvious way to reduce the overhead).
       >
       > Link to size graph:
[https://chromeperf.appspot.com/report?sid=6468aba6ff8d28723690042144ee893d2dd3ded7fb414a916520b90659b8410f&rev=**440074**](https://chromeperf.appspot.com/report?sid=6468aba6ff8d28723690042144ee893d2dd3ded7fb414a916520b90659b8410f&rev=440074)
    2. Add an entry to
      [this spreadsheet](https://docs.google.com/spreadsheets/d/1GrRkszV7Oy5pVsaMb5Eb6s8izW9t4dElBxIH3iGq93o/edit#gid=1894856744)
      to document the increase (also Update the "Themes / Thoughts" tab if
      applicable).
 * If the code might not justify the size increase:
    1. File a bug and assign to the author to follow-up (and link them to this
       doc).
    2. Add an entry to
      [this spreadsheet](https://docs.google.com/spreadsheets/d/1GrRkszV7Oy5pVsaMb5Eb6s8izW9t4dElBxIH3iGq93o/edit#gid=1894856744)
      to document the increase.

# Debugging Apk Size Increase

### How to debug apk size increase

1. Figure out which file within the .apk increased by looking at the size
   graphs showing the breakdowns.
    * Refer to the chromeperf link that should have been posted to your code review
      (see above).
    * Alternatively, refer to "Apk Size" section here:
      [https://goto.google.com/clank/dashboards](https://goto.google.com/clank/dashboards) (*googler only*).
1. If it's libchrome.so, build before & after and use
   [tools/binary_size/](https://cs.chromium.org/chromium/src/tools/binary_size/).
    * This is somewhat hand-wavy. Some notes on how this tool works at
      [crbug/482401](https://bugs.chromium.org/p/chromium/issues/detail?id=482401).
1. If it's classes.dex, build before & after and use:
   [tools/android/dexdiffer/dexdiffer.py](https://cs.chromium.org/chromium/src/tools/android/dexdiffer/dexdiffer.py).
    * This currently just shows a list of symbols added / removed rather than
      taking into account method body sizes.
    * Enhancements to this tool tracked at
      [crbug/678044](https://bugs.chromium.org/p/chromium/issues/detail?id=678044).
1. If it's images, ensure they are optimized:
    * Would it be smaller as a VectorDrawable?
    * If it's lossy, consider using webp.
    * Ensure you've optimized with
      [tools/resources/optimize-png-files.sh](https://cs.chromium.org/chromium/src/tools/resources/optimize-png-files.sh).

