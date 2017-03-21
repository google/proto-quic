### Updating APKs in this folder (for new milestones, builders, or APKs)

1. Find the commit as close as possible to the current branch point (i.e. if the
latest builds are m59, we want to compare to the commit before the m58 branch
point).

2. Download and unzip build artifacts from the relevant perf builder. You can
use this link:
[https<nolink>://storage.cloud.google.com/chrome-perf/**Android%20Builder**/full-build-linux_**3a87aecc31cd1ffe751dd72c04e5a96a1fc8108a**.zip](https://storage.cloud.google.com/chrome-perf/Android%20Builder/full-build-linux_3a87aecc31cd1ffe751dd72c04e5a96a1fc8108a.zip)
, replacing the bolded parts with your info OR from the
"gsutil upload_build_product" step on the bot page (both are Googlers only).

3. Upload the apk: _upload_to_google_storage.py --bucket
'chromium-android-tools/apks/**Android_Builder**/**58**'
**path/to/ApkTarget.apk**_ replacing the bolded parts again.
  * Note that we use **Android_Builder** instead of **Android Builder** (replace
spaces with underscores)

4. Move the generated .sha1 file to the corresponding place in
//build/android/binary_size/apks/. In this case, the path would be
//build/android/binary_size/apks/Android_Builder/58

5. Commit the added .sha1 files and (optionally) update the `CURRENT_MILESTONE`
in apk_downloader.py
