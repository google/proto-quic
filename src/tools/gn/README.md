# What is GN?

GN is a meta-build system that generates
[NinjaBuild](https://chromium.googlesource.com/chromium/src/+/master/docs/ninja_build.md)
files so that you can build Chromium with Ninja.

## Why did you switch from GYP?

1. We believe GN files are more readable and more maintainable than GYP files.
2. GN is fast:
  * GN is 20x faster than GYP.
  * GN supports automatically re-running itself as needed by Ninja
    as part of the build. This eliminates the need to remember to
    re-run GN when you change a build file.
3. GN gives us better tools for enforcing dependencies (see
   `gn check` and the `visibility`, `public_deps`, and `data_deps`
   options for some examples).
4. GN gives us tools for querying the build graph; you can ask
   "what does X depend on" and "who depends on Y", for example.

## What's the status of the GYP->GN migration?

_As of Oct 2016:_

  * All of the Chromium builds have been switched over.
  * Nearly all of the GYP files have been deleted from the Chromium repos.
  * You can no longer build with GYP as a result.
  * There are still some GYP files in place for the "Closure Compilation"
    builders that need to be converted over.
  * Some related projects (e.g., V8, Skia) may still support GYP for their
    own reasons.
  * We're still cleaning up some odds and ends like making gclient not
    still use GYP_DEFINES.

## I want more info on GN!

Read these links:

  * [Quick start](https://chromium.googlesource.com/chromium/src/+/master/tools/gn/docs/quick_start.md)
  * [FAQ](https://chromium.googlesource.com/chromium/src/+/master/tools/gn/docs/faq.md)
  * [GYP conversion cookbook](https://chromium.googlesource.com/chromium/src/+/master/tools/gn/docs/cookbook.md)
  * [Language and operation details](https://chromium.googlesource.com/chromium/src/+/master/tools/gn/docs/language.md)
  * [Reference](https://chromium.googlesource.com/chromium/src/+/master/tools/gn/docs/reference.md) The built-in `gn help` documentation.
  * [Style guide](https://chromium.googlesource.com/chromium/src/+/master/tools/gn/docs/style_guide.md)
  * [Cross compiling and toolchains](https://chromium.googlesource.com/chromium/src/+/master/tools/gn/docs/cross_compiles.md)
  * [Hacking on GN itself](https://chromium.googlesource.com/chromium/src/+/master/tools/gn/docs/hacking.md)
  * [GNStandalone](https://chromium.googlesource.com/chromium/src/+/master/tools/gn/docs/standalone.md) Standalone GN projects
  * [UpdateGNBinaries](https://chromium.googlesource.com/chromium/src/+/master/tools/gn/docs/update_binaries.md) Pushing new binaries
  * [Check](https://chromium.googlesource.com/chromium/src/+/master/tools/gn/docs/check.md) `gn check` command reference
