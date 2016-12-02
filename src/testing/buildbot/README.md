# Buildbot Testing Configuration Files

The files in this directory control how tests are run on the
[Chromium buildbots](https://www.chromium.org/developers/testing/chromium-build-infrastructure/tour-of-the-chromium-buildbot).
In addition to specifying what tests run on which builders, they also specify
special arguments and constraints for the tests.

## A tour of the directory
* <master_name\>.json -- buildbot configuration json files. These are used to
configure what tests are run on what builders, in addition to specifying
builder-specific arguments and parameters.
* [gn_isolate_map.pyl](./gn_isolate_map.pyl) -- maps Ninja build target names
to GN labels. Allows for certain overrides to get certain tests targets to work
with GN (and properly run when isolated).
* [trybot_analyze_config.json](./trybot_analyze_config.json) -- used to provide
exclusions to
[the analyze step](https://www.chromium.org/developers/testing/commit-queue/chromium_trybot-json)
on trybots.
* [filters/](./filters/) -- filters out tests that shouldn't be
run in a particular mode.
* [timeouts.py](./timeouts.py) -- calculates acceptable timeouts for tests by
analyzing their execution on
[swarming](https://github.com/luci/luci-py/tree/master/appengine/swarming).
* [manage.py](./manage.py) -- makes sure the buildbot configuration json is in
a standardized format.

## How the files are consumed
### Buildbot configuration json
Logic in the
[Chromium recipe](https://chromium.googlesource.com/chromium/tools/build/+/refs/heads/master/scripts/slave/recipes/chromium.py)
looks up each builder for each master and test generators in
[chromium_tests/steps.py](https://chromium.googlesource.com/chromium/tools/build/+/refs/heads/master/scripts/slave/recipe_modules/chromium_tests/steps.py)
parse the data. For example, as of
[a6e11220](https://chromium.googlesource.com/chromium/tools/build/+/a6e11220d97d578d6ba091abd68beba28a004722)
[generate_gtest](https://chromium.googlesource.com/chromium/tools/build/+/a6e11220d97d578d6ba091abd68beba28a004722/scripts/slave/recipe_modules/chromium_tests/steps.py#416)
parses any entry in a builder's
['gtest_tests'](https://chromium.googlesource.com/chromium/src/+/5750756522296b2a9a08009d8d2cc90db3b88f56/testing/buildbot/chromium.android.json#1243)
entry.

## How to edit
### Making the changes
#### Buildbot configuration json
After editing any buildbot json, run `./manage.py -w` to load and write in the
canonical format. Then commit as normal.

Note that trybots mirror regular waterfall bots, with the mapping defined in
[trybots.py](https://chromium.googlesource.com/chromium/tools/build/+/refs/heads/master/scripts/slave/recipe_modules/chromium_tests/trybots.py).
This means that, as of
[81fcc4bc](https://chromium.googlesource.com/chromium/src/+/81fcc4bc6123ace8dd37db74fd2592e3e15ea46a/testing/buildbot/),
if you want to edit
[linux_android_rel_ng](https://chromium.googlesource.com/chromium/tools/build/+/59a2653d5f143213f4f166714657808b0c646bd7/scripts/slave/recipe_modules/chromium_tests/trybots.py#142),
you actually need to edit
[Android Tests](https://chromium.googlesource.com/chromium/src/+/81fcc4bc6123ace8dd37db74fd2592e3e15ea46a/testing/buildbot/chromium.linux.json#23).

### Trying the changes on trybots
You should be able to try build changes that affect the trybots directly (for
example, adding a test to linux_android_rel_ng should show up immediately in
your tryjob). Non-trybot changes have to be landed manually :(.

## Capacity considerations when editing the buildbot configuration json
When adding tests or bumping timeouts in the buildbot configuration json, care
must be taken to ensure the infrastructure has capacity to handle the extra
load.  This is especially true for the established
[Chromium CQ builders](https://chromium.googlesource.com/chromium/src/+/master/infra/config/cq.cfg),
as they operate under strict execution requirements. Make sure to get an
infrastructure engineer on the Crossover Team to sign off that there is both
buildbot and swarming capacity available.
