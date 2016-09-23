# What is GN?

GN is a meta-build system that generates
[NinjaBuild](https://chromium.googlesource.com/chromium/src/+/master/docs/ninja_build.md)
files. It's meant to be faster and simpler than GYP. It outputs only Ninja build
files.

## Why bother with GN?

1. We believe GN files are more readable and more maintainable
   than GYP files.
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

## What's the status?

_as of March 2016:_

  * Linux and Android: Complete but not quite all bots have been flipped.
    Developers should be using GN on these platforms for most work.
  * Windows and ChromeOS: Should be usable for almost all development. Some
    bots need to be flipped. cros_sdk builds don't work on ChromeOS yet.
  * Mac and iOS: Work is in progress, generally not usable for normal
    development.

## When are you going to be done?

_as of March 2016:_

We expect most work to be finishing up between now and the end of Q2.

## What does "done" mean?

Ideally we're done when all of the GYP files have been deleted from
Chromium and no one misses them.

We will be "mostly" done when the following are true:

  * All of the bots maintained by the Chrome infra team for Chromium and
    downstream of Chromium have been switched to GN. (Upstream projects
    like Skia and V8 can choose to stay on GYP if they like).
  * Any developer configurations we care about that don't have bots also
    work (Generally speaking, we're aiming to not have any of these.
  * Configurations we care about should have bots to ensure they don't
    break).  We have verified that all of the tests pass.  We have
    verified that the command lines match in the above configurations as
    much as possible, and we accept any differences.  We have reviewed
    any binary differences that result in the official builds and
    accepted them.  The GN files are the "source of truth" for the
    build, and normal chromium developers normally do not need to touch
    GYP files to keep things working.  We have replacements for the
    hybrid "msvs-ninja" and "xcode-ninja" configurations that GYP can
    currently build.

The difference between "mostly done" and "done" exists to cover any
issues we haven't yet identified :)

## How can I help?

We could especially use infrastructure/bot, Mac, and iOS help.

Or, look at [the list of open bugs](https://code.google.com/p/chromium/issues/list?can=2&q=label:Proj-GN-Migration%20-type:Project&sort=pri&colspec=ID%20Pri%20Summary%20Type%20OS%20Owner%20Status%20Modified%20Blocking) related to the migration and see if there's anything that catches your fancy.

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
