# Perf Bot Sheriffing

The perf bot sheriff is responsible for keeping the bots on the chromium.perf
waterfall up and running, and triaging performance test failures and flakes.

**[Rotation calendar](https://calendar.google.com/calendar/embed?src=google.com_2fpmo740pd1unrui9d7cgpbg2k%40group.calendar.google.com)**

## Key Responsibilities

*   [Handle Device and Bot Failures](#Handle-Device-and-Bot-Failures)
*   [Handle Test Failures](#Handle-Test-Failures)
*   [Follow up on failures](#Follow-up-on-failures)

## Understanding the Waterfall State

**[Sheriff-O-Matic](https://sheriff-o-matic.appspot.com/chromium.perf)** is (as of
2/27/2017) the recommended way to perfbot sheriff. It can be used to track the
different issues and associate them with specific bugs, and annotate failures
with useful information. It also attempts to group together similar failures
across different builders, so it can help to see a higher level perspective on
what is happening on the perf waterfall.

It is an actively staffed project, which should be getting better over time. If
you find any bugs with the app, you can file a bug by clicking on the feedback
link in the bottom right of the app, or by clicking this [link](https://bugs.chromium.org/p/chromium/issues/entry?template=Build%20Infrastructure&components=Infra%3ESheriffing%3ESheriffOMatic&labels=Pri-2,Infra-DX&cc=seanmccullough@chromium.org,martiniss@chromium.org,zhangtiff@chromium.org&comment=Problem+with+Sheriff-o-Matic).

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

### Android Cross-Device Failures

Sometimes when looking at failing android tests you will notice that there are
tests on multiple devices failing. Sometimes (but not always) this means that
there is a problem on the host machine. One way this problem can occur is if
a test is using the wrong version of adb in one of its commands. This causes
the adb server on the host to reset which can cause failures to anything
trying to communicate with a device via adb during that time. A good tool
for diagnosing this is the **Test Trace** step on the android runs. This is a
trace of which tests are running. If you have all the tests across all the
testing shards failing, it may be an issue on the host not with the tests.
This will no longer be used when the android bots move to swarming, since
each device will be sandboxed from the others and not run from a single
point.


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

### Useful Logs and Debugging Info

1. **Telemetry test runner logs**

    **_Useful Content:_** Best place to start. These logs contain all of the
    python logging information from the telemetry test runner scripts.

    **_Where to find:_** These logs can be found from the buildbot build page.
    Click the _"[stdout]"_ link under any of the telemetry test buildbot steps
    to view the logs. Do not use the "stdio" link which will show similiar
    information but will expire earilier and be slower to load.

2. **Android Logcat (Android)**

    **_Useful Content:_** This file contains all Android device logs. All
    Android apps and the Android system will log information to logcat. Good
    place to look if you believe an issue is device related
    (Android out-of-memory problem for example). Additionally, often information
    about native crashes will be logged to here.

    **_Where to find:_** These logs can be found from the buildbot status page.
    Click the _"logcat dump"_ link under one of the _"gsutil upload"_ steps.

3. **Test Trace (Android)**

    **_Useful Content:_** These logs graphically depict the start/end times for
    all telemetry tests on all of the devices. This can help determine if test
    failures were caused by an environmental issue.
    (see [Cross-Device Failures](#Android-Cross-Device-Failures))

    **_Where to find:_** These logs can be found from the buildbot status page.
    Click the _"Test Trace"_ link under one of the
    _"gsutil Upload Test Trace"_ steps.

4. **Symbolized Stack Traces (Android)**

    **_Useful Content:_** Contains symbolized stack traces of any Chrome or
    Android crashes.

    **_Where to find_:** These logs can be found from the buildbot status page.
    The symbolized stack traces can be found under several steps. Click link
    under _"symbolized breakpad crashes"_ step to see symbolized Chrome crashes.
    Click link under _"stack tool with logcat dump"_ to see symbolized Android
    crashes.

## Swarming Bots
As of Q4 2016 all desktop bots have been moved to the swarming pool with a goal
of moving all android bots to swarming in early 2017.  There is now one machine
on the chromium.perf waterfall for each desktop configuration that is triggering
test tasks on 5 corresponding swarming bots.  All of our swarming bots exists in
the [chrome-perf swarming pool](https://chromium-swarm.appspot.com/botlist?c=id&c=os&c=task&c=status&f=pool%3AChrome-perf&l=100&s=id%3Aasc)

1.  Buildbot status page FYIs
    *   Every test that is run now has 2-3 recipe steps on the buildbot status
        page associated with it
        1.  '[trigger] <test_name>' step (you can mostly ignore this)
        2.  '<test_name>' This is the test that was run on the swarming bot,
            'shard #0' link on the step takes you to the swarming task page
        3.  '<test_name> Dashboard Upload' This is the upload of the perf tests
            results to the perf dashboard.  This will not be present if the test
            was disabled.
    *   We now run all benchmark tests even if they are disabled, but disabled
        tests will always return success and you can ignore them.  You can
        identify these by the 'DISABLED_BENCHMARK' link under the step and the
        fact that they don’t have an upload step after them
2.  Debugging Expiring Jobs on the waterfall
    *   You can tell a job is expiring in one of two ways:
        1.  Click on the 'shard #0' link of the failed test and you will see
            EXPIRED on the swarming task page
        2.  If there is a 'no_results_exc' and an 'invalid_results_exc' link on
            the buildbot failing test step with the dashboard upload step
            failing (Note: this could be an EXPIRED job or a TIMEOUT.  An
            Expired job means the task never got scheduled within the 5 hour
            swarming timeout and TIMEOUT means it started running but couldn’t
            finish before the 5 hour swarming timeout)
    *   You can quickly see what bots the jobs are expiring/timing out on with
        the ‘Bot id’ annotation on the failing test step
    *   Troubleshooting why they are expiring
        1.  Bot might be down, check the chrome-perf pool for that bot-id and
            file a ticket with go/bugatrooper if the bot is down.
            *   Can also identify a down bot through [viceroy](https://viceroy.corp.google.com/chrome_infra/Machines/per_machine)
                Search for a bot id and if the graph stops it tells you the bot
                is down
        2.  Otherwise check the bots swarming page task list for each bot that
            has failing jobs and examine what might be going on  (good [video](https://youtu.be/gRa0LvICthk)
            from maruel@ on the swarming ui and how to filter and search bot
            task lists.  For example you can filter on bot-id and name to
            examine the last n runs of a test).
            *   A test might be timing out on a bot that is causing subsequent
                tests to expire even though they would pass normally but never
                get scheduled due to that timing out test.  Debug the timing out
                test.
            *   A test might be taking a longer time than normal but still
                passing, but the extra execution time causes other unrelated
                tests to fail.  Examine the last passing run to the first
                failing run and see if you can see a test that is taking a
                significantly longer time and debug that issue.
3.  Reproducing swarming task runs
    *   Reproduce on local machine using same inputs as bot
        1.  Note that the local machines spec must roughly match that of the
            swarming bot
        2.  See 'Reproducing the task locally' on swarming task page
        3.  First run the command under
            'Download input files into directory foo'
        4.  cd into foo/out/Release if those downloaded inputs
        5.  Execute test from this directory.  Command you are looking for
            should be at the top of the logs, you just need to update the
            `--isolated-script-test-output=/b/s/w/ioFB73Qz/output.json` and
            `--isolated-script-test-chartjson-output=/b/s/w/ioFB73Qz/chartjson-output.json`
            flags to be a local path
        6.  Example with tmp as locally created dir:
            `/usr/bin/python ../../testing/scripts/run_telemetry_benchmark_as_googletest.py ../../tools/perf/run_benchmark speedometer -v --upload-results --output-format=chartjson --browser=release --isolated-script-test-output=tmp/output.json --isolated-script-test-chartjson-output=tmp/chartjson-output.json`
    *   ssh into swarming bot and run test on that machine
        1.  NOTE: this should be a last resort since it will cause a fifth of
            the benchmarks to continuously fail on the waterfall
        2   First you need to decommission the swarming bot so other jobs don’t
            interfere, file a ticket with go/bugatrooper
        3.  See [remote access to bots](https://sites.google.com/a/google.com/chrome-infrastructure/golo/remote-access?pli=1)
            on how to ssh into the bot and then run the test.
            Rough overview for build161-m1
            *   prodaccess --chromegolo_ssh
            *   Ssh build161-m1.golo
            *   Password is in valentine
                "Chrome Golo, Perf, GPU bots - chrome-bot"
            *   File a bug to reboot the machine to get it online in the
                swarming pool again
4. Running local changes on swarming bot
    *   Using sunspider as example benchmark since it is a quick one
    *   First, run test locally to make sure there is no issue with the binary
        or the script running the test on the swarming bot.  Make sure dir foo
        exists:
        `python testing/scripts/run_telemetry_benchmark_as_googletest.py tools/perf/run_benchmark sunspider -v --output-format=chartjson --upload-results --browser=reference --output-trace-tag=_ref --isolated-script-test-output=foo/output.json --isolated-script-test-chartjson-output=foo/chart-output.json`
    *   Build any dependencies needed in isolate:
        1.  ninja -C out/Release chrome/test:telemetry_perf_tests
        2.  This target should be enough if you are running a benchmark,
            otherwise build any targets that they say are missing when building
            the isolate in step #2.
        3.   Make sure [compiler proxy is running](https://sites.google.com/a/google.com/goma/how-to-use-goma/how-to-use-goma-for-chrome-team?pli=1)
            *   ./goma_ctl.py ensure_start from goma directory
    *   Build the isolate
        1. `python tools/mb/mb.py isolate //out/Release -m chromium.perf -b "Linux Builder" telemetry_perf_tests`
            *   -m is the master
            *   -b is the builder name from mb_config.pyl that corresponds to
                the platform you are running this command on
            *   telemetry_perf_tests is the isolate name
            *   Might run into internal source deps when building the isolate,
                depending on the isolate.  Might need to update the entry in
                mb_config.pyl for this builder to not be an official built so
                src/internal isn’t required
    *   Archive and create the isolate hash
        1.  `python tools/swarming_client/isolate.py archive -I isolateserver.appspot.com -i out/Release/telemetry_perf_tests.isolate -s out/Release/telemetry_perf_tests.isolated`
    *   Run the test with the has from step #3
        1.  Run hash locally
            *   Note output paths are local
            *   `./tools/swarming_client/run_isolated.py -I https://isolateserver.appspot.com -s <insert_hash_here> -- sunspider -v --upload-results --output-format=chartjson --browser=reference --output-trace-tag=_ref --isolated-script-test-output=/usr/local/google/home/eyaich/projects/chromium/src/tmp/output.json`
        2.  Trigger on swarming bot
            *   Note paths are using swarming output dir environment variable
                ISOLATED_OUTDIR and dimensions are based on the bot and os you
                are triggering the job on
            *   `python tools/swarming_client/swarming.py trigger -v --isolate-server isolateserver.appspot.com -S chromium-swarm.appspot.com -d id build150-m1 -d pool Chrome-perf -d os Linux -s <insert_hash_here> -- sunspider -v --upload-results --output-format=chartjson --browser=reference --output-trace-tag=_ref -isolated-script-test-output='${ISOLATED_OUTDIR}/output.json' --isolated-script-test-chartjson-output='${ISOLATED_OUTDIR}/chart-output.json'`
            *   All args after the '--' are for the swarming task and not for
                the trigger command.  The output dirs must be in quotes when
                triggering on swarming bot

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
Update tools/perf/generate_perf_data.py to disable the test and rerun script to
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

## Shift Hand-off

At the end of your shift you should send out a message to the next sheriff It
should detail any ongoing issues you are trying to resolve. This can contain new
bugs you have filed and bisects you are waiting to finish. If there has been any
significant updates on older issues that the next sheriff should know about they
should also be included. This will greatly decrease the amount of time needed
for the next sheriff to come up to speed.

There is also a weekly debrief that you should see on your calendar titled
**Weekly Speed Sheriff Retrospective**. For this meeting you should prepare
any highlights or lowlights from your sheriffing shift as well as any other
feedback you may have that could improve future sheriffing shifts.

<!-- Unresolved issues:
1. Do perf sheriffs watch the bisect waterfall?
2. Do perf sheriffs watch the internal clank waterfall?
-->
