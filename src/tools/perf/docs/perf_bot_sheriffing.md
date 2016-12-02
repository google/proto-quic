# Perf Bot Sheriffing

The perf bot sheriff is responsible for keeping the bots on the chromium.perf
waterfall up and running, and triaging performance test failures and flakes.

**[Rotation calendar](https://calendar.google.com/calendar/embed?src=google.com_2fpmo740pd1unrui9d7cgpbg2k%40group.calendar.google.com)**

## Key Responsibilities

*   [Handle Device and Bot Failures](#Handle-Device-and-Bot-Failures)
*   [Handle Test Failures](#Handle-Test-Failures)
*   [Follow up on failures](#Follow-up-on-failures)

## Understanding the Waterfall State

Everyone can view the chromium.perf waterfall at
https://build.chromium.org/p/chromium.perf/, but for Googlers it is recommended
that you use the url https://uberchromegw.corp.google.com/i/chromium.perf/ instead.
The reason for this is that in order to make the performance tests as realistic as
possible, the chromium.perf waterfall runs release official builds of Chrome.
But the logs from release official builds may leak info from our partners that
we do not have permission to share outside of Google. So the logs are available
to Googlers only. To avoid manually rewriting the URL when switching between
the upstream and downstream views of the waterfall and bots, you can install the
[Chromium Waterfall View Switcher extension](https://chrome.google.com/webstore/a/google.com/detail/chromium-waterfall-view-s/hnnplblfkmfaadpjdpkepbkdjhjpjbdp),
which adds a switching button to Chrome's URL bar.

Note that there are three different views:

1.  [Console view](https://uberchromegw.corp.google.com/i/chromium.perf/) makes
    it easier to see a summary.
2.  [Waterfall view](https://uberchromegw.corp.google.com/i/chromium.perf/waterfall)
    shows more details, including recent changes.
3.  [Firefighter](https://chromiumperfstats.appspot.com/) shows traces of
    recent builds. It takes url parameter arguments:
    *   **master** can be chromium.perf, tryserver.chromium.perf
    *   **builder** can be a builder or tester name, like
        "Android Nexus5 Perf (2)"
    *   **start_time** is seconds since the epoch.


There is also [milo](https://luci-milo.appspot.com), which has the same data as
buildbot, but mirrored in a different datastore. It is generally faster than
buildbot, and links to it will not break, as the data is kept around for much
longer.

In addition to watching the waterfall directly,
[Sheriff-O-Matic](https://sheriff-o-matic.appspot.com/chromium.perf) may
optionally be used to easily track the different issues and associate
them with specific bugs. It also attempts to group together similar failures
across different builders, so it can help to see a higher level perspective on
what is happening on the perf waterfall.

You can see a list of all previously filed bugs using the
**[Performance-Sheriff-BotHealth](https://bugs.chromium.org/p/chromium/issues/list?can=2&q=label%3APerformance-Sheriff-BotHealth)**
label in crbug.

Please also check the recent
**[perf-sheriffs@chromium.org](https://groups.google.com/a/chromium.org/forum/#!forum/perf-sheriffs)**
postings for important announcements about bot turndowns and other known issues.

## Handle Device and Bot Failures

### Offline Buildslaves

Some build configurations, in particular the perf builders and trybots, have
multiple machines attached. If one or more of the machines go down, there are
still other machines running, so the console or waterfall view will still show
green, but those configs will run at reduced throughput. At least once during
your shift, you should check the lists of buildslaves and ensure they're all
running.

*   [chromium.perf buildslaves](https://build.chromium.org/p/chromium.perf/buildslaves)
*   [tryserver.chromium.perf buildslaves](https://build.chromium.org/p/tryserver.chromium.perf/buildslaves)

The machines restart between test runs, so just looking for "Status: Not
connected" is not enough to indicate a problem. For each disconnected machine,
you can also check the "Last heard from" column to ensure that it's been gone
for at least an hour. To get it running again,
[file a bug](https://bugs.chromium.org/p/chromium/issues/entry?labels=Pri-1,Performance-Sheriff-BotHealth,Infra-Troopers,OS-?&comment=Hostname:&summary=Buildslave+offline+on+chromium.perf)
against the current trooper and read [go/bug-a-trooper](http://go/bug-a-trooper)
for contacting troopers.

The chrome infrastructure team also maintains a set of dashboards you can use to
view some debugging information about our systems. This is available at
[vi/chrome_infra](http://vi/chrome_infra). To debug offline buildslaves,
you can look at the "Individual machine" dashboard, (at
[vi/chrome_infra/Machines/per_machine](http://vi/chrome_infra/Machines/per_machine)
under the "Machines" section, which can show some useful information about the
machine in question.

### Purple bots

When a bot goes purple, it's usually because of an infrastructure failure
outside of the tests. But you should first check the logs of a purple bot to
try to better understand the problem. Sometimes a telemetry test failure can
turn the bot purple, for example.

If the bot goes purple and you believe it's an infrastructure issue, file a bug
with
[this template](https://bugs.chromium.org/p/chromium/issues/entry?labels=Pri-1,Performance-Sheriff-BotHealth,Infra-Troopers,OS-?&comment=Link+to+buildbot+status+page:&summary=Purple+Bot+on+chromium.perf),
which will automatically add the bug to the trooper queue. Be sure to note
which step is failing, and paste any relevant info from the logs into the bug. Also be sure to read [go/bug-a-trooper](http://go/bug-a-trooper) for contacting troopers.

### Android Device failures

There are three types of device failures:

1.  A device is blacklisted in the `device_status` step. Device failures of this
    type are expected to be purple. You can look at the buildbot status page to
    see how many devices were listed as online during this step. You should
    always see 7 devices online. If you see fewer than 7 devices online, there
    is a problem in the lab.
2.  A device is passing `device_status` but still in poor health. The
    symptom of this is that all the tests are failing on it. You can see that on
    the buildbot status page by looking at the `Device Affinity`. If all tests
    with the same device affinity number are failing, it's probably a device
    failure.
3.  A device has completely disappeared from `device_status` step. You should
    always see 7 total devices on a bot in one of three statuses: online,
    misisng, or blacklisted. If you see fewer than 7 devices it means there is
    a problem with the known devices persistent file and the device is
    unreachable via adb. This usually means the known devices file was cleared
    while a device was unreachable. A bug should be filed saying that there is a
    missing device. Going through previous logs will usually yield a device ID
    for the missing device.

For these types of failures, please file a bug with
[this template](https://bugs.chromium.org/p/chromium/issues/entry?components=Infra%3ELabs&labels=Pri-1,Performance-Sheriff-BotHealth,OS-Android&comment=Link+to+buildbot+status+page:&summary=Device+offline+on+chromium.perf)
which will add an issue to the infra labs queue.

If you need help triaging, here are the common labels you should use:

*   **Performance-Sheriff-BotHealth** should go on all bugs you file about the bots;
    it's the label we use to track all the issues.
*   **Infra-Troopers** adds the bug to the trooper queue. This is for high
    priority issues, like a build breakage. Please add a comment explaining what
    you want the trooper to do.


Here are the common components you should also use:

*   **Infra>Labs** adds the bug to the labs queue. If there is a hardware
    problem, like an android device not responding or a bot that likely needs a
    restart, please use this label. Make sure you set the **OS-** label
    correctly as well, and add a comment explaining what you want the labs team
    to do.
*   **Infra** label is appropriate for bugs that are not high priority, but we
    need infra team's help to triage. For example, the buildbot status page UI
    is weird or we are getting some infra-related log spam. The infra team works
    to triage these bugs within 24 hours, so you should ping if you do not get a
    response.
*   **Tests>Telemetry** for telemetry failures.
*   **Tests>AutoBisect** for bisect and perf try job failures.

 If you still need help, ask the speed infra chat, or escalate to sullivan@.

### Clobbering

Sometimes when a compile step is failing, you may be asked to clobber
[example](https://bugs.chromium.org/p/chromium/issues/detail?id=598955#c7).
Steps to clobber:

1.  Open the builder page through
    [uberchromegw](https://uberchromegw.corp.google.com/i/chromium.perf).
2.  At the bottom, there is a form titled **"Force build"**.
3.  Fill out the force build form, including your username, the reason for the
    clobber with crbug id if possible, and checking the **"Clobber"** box.
4.  Click the "Force Build" button.

## Handle Test Failures

You want to keep the waterfall green! So any bot that is red or purple needs to
be investigated. When a test fails:

1.  File a bug using
    [this template](https://bugs.chromium.org/p/chromium/issues/entry?labels=Performance-Sheriff-BotHealth,Pri-1,Type-Bug-Regression,OS-?&comment=Revision+range+first+seen:%0ALink+to+failing+step+log:%0A%0A%0AIf%20the%20test%20is%20disabled,%20please%20downgrade%20to%20Pri-2.&summary=%3Ctest%3E+failure+on+chromium.perf+at+%3Crevisionrange%3E).
    You'll want to be sure to include:
    *   Link to buildbot status page of failing build.
    *   Copy and paste of relevant failure snippet from the stdio.
    *   CC the test owner from
        [go/perf-owners](https://docs.google.com/spreadsheets/d/1xaAo0_SU3iDfGdqDJZX_jRV0QtkufwHUKH3kQKF3YQs/edit#gid=0).
    *   The revision range the test occurred on.
    *   A list of all platforms the test fails on.
2.  Disable the failing test if it is failing more than one out of five runs.
    (see below for instructions on telemetry and other types of tests). Make
    sure your disable cl includes a BUG= line with the bug from step 1 and the
    test owner is cc-ed on the bug.
3.  After the disable CL lands, you can downgrade the priority to Pri-2 and
    ensure that the bug title reflects something like "Fix and re-enable
    testname".
4.  Investigate the failure. Some tips for investigating:
    *   If it's a non flaky failure, indentify the first failed
        build so you can narrow down the range of CLs that causes the failure.
        You can use the
        [diagnose_test_failure](https://code.google.com/p/chromium/codesearch#chromium/src/tools/perf/diagnose_test_failure)
        script to automatically find the first failed build and the good & bad
        revisions (which can also be used for return code bisect).
    *   If you suspect a specific CL in the range, you can revert it locally and
        run the test on the
        [perf trybots](https://www.chromium.org/developers/telemetry/performance-try-bots).
    *   You can run a return code bisect to narrow down the culprit CL:
        1.  Open up the graph in the [perf dashboard](https://chromeperf.appspot.com/report)
            on one of the failing platforms.
        2.  Hover over a data point and click the "Bisect" button on the
            tooltip.
        3.  Type the **Bug ID** from step 1, the **Good Revision** the last
            commit pos data was received from, the **Bad Revision** the last
            commit pos and set **Bisect mode** to `return_code`.
    *   [Debugging telemetry failures](https://www.chromium.org/developers/telemetry/diagnosing-test-failures)
    *   On Android and Mac, you can view platform-level screenshots of the
        device screen for failing tests, links to which are printed in the logs.
        Often this will immediately reveal failure causes that are opaque from
        the logs alone. On other platforms, Devtools will produce tab
        screenshots as long as the tab did not crash.

### Disabling Telemetry Tests

If the test is a telemetry test, its name will have a '.' in it, such as
`thread_times.key_mobile_sites` or `page_cycler.top_10`. The part before the
first dot will be a python file in [tools/perf/benchmarks](https://code.google.com/p/chromium/codesearch#chromium/src/tools/perf/benchmarks/).

If a telemetry test is failing and there is no clear culprit to revert
immediately, disable the test. You can do this with the `@benchmark.Disabled`
decorator. **Always add a comment next to your decorator with the bug id which
has background on why the test was disabled, and also include a BUG= line in
the CL.**

Please disable the narrowest set of bots possible; for example, if
the benchmark only fails on Windows Vista you can use
`@benchmark.Disabled('vista')`. Supported disabled arguments include:

*   `win`
*   `mac`
*   `chromeos`
*   `linux`
*   `android`
*   `vista`
*   `win7`
*   `win8`
*   `yosemite`
*   `elcapitan`
*   `all` (please use as a last resort)

If the test fails consistently in a very narrow set of circumstances, you may
consider implementing a `ShouldDisable` method on the benchmark instead.
[Here](https://code.google.com/p/chromium/codesearch#chromium/src/tools/perf/benchmarks/power.py&q=svelte%20file:%5Esrc/tools/perf/&sq=package:chromium&type=cs&l=72) is
and example of disabling a benchmark which OOMs on svelte.

As a last resort, if you need to disable a benchmark on a particular Android
device, you can do so by checking the return value of
`possible_browser.platform.GetDeviceTypeName()` in `ShouldDisable`. Here are
some [examples](https://code.google.com/p/chromium/codesearch#search/&q=ShouldDisable%20GetDeviceTypeName%20lang:py&sq=package:chromium&type=cs)
of this. The type name of the failing device can be found by searching for the
value of `ro.product.model` under the `provision_devices` step of the failing
bot.

Disabling CLs can be TBR-ed to anyone in [tools/perf/OWNERS](https://code.google.com/p/chromium/codesearch#chromium/src/tools/perf/OWNERS),
but please do **not** submit with NOTRY=true.

### Disabling Other Tests

Non-telemetry tests are configured in [chromium.perf.json](https://code.google.com/p/chromium/codesearch#chromium/src/testing/buildbot/chromium.perf.json) **But do not manually edit this file.**
Update tools/perf/generate_perf_json.py to disable the test and rerun script to
generate the new chromium.perf.json file.
You can TBR any of the per-file OWNERS, but please do **not** submit with
NOTRY=true.

## Follow up on failures

**[Pri-0 bugs](https://bugs.chromium.org/p/chromium/issues/list?can=2&q=label%3APerformance-Sheriff-BotHealth+label%3APri-0)**
should have an owner or contact on speed infra team and be worked on as top
priority. Pri-0 generally implies an entire waterfall is down.

**[Pri-1 bugs](https://bugs.chromium.org/p/chromium/issues/list?can=2&q=label%3APerformance-Sheriff-BotHealth+label%3APri-1)**
should be pinged daily, and checked to make sure someone is following up. Pri-1
bugs are for a red test (not yet disabled), purple bot, or failing device. Here
is the [list of Pri-1 bugs that have not been pinged today](https://bugs.chromium.org/p/chromium/issues/list?can=2&q=label:Performance-Sheriff-BotHealth%20label:Pri-1%20modified-before:today-1&sort=modified).

**[Pri-2 bugs](https://bugs.chromium.org/p/chromium/issues/list?can=2&q=label%3APerformance-Sheriff-BotHealth+label%3APri-2)**
are for disabled tests. These should be pinged weekly, and work towards fixing
should be ongoing when the sheriff is not working on a Pri-1 issue. Here is the
[list of Pri-2 bugs that have not been pinged in a week](https://bugs.chromium.org/p/chromium/issues/list?can=2&q=label:Performance-Sheriff-BotHealth%20label:Pri-2%20modified-before:today-7&sort=modified).

<!-- Unresolved issues:
1. Do perf sheriffs watch the bisect waterfall?
2. Do perf sheriffs watch the internal clank waterfall?
-->
