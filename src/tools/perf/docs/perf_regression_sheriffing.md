# Perf Regression Sheriffing (go/perfregression-sheriff)

The perf regression sheriff tracks performance regressions in Chrome's
continuous integration tests. Note that a [new rotation](perf_bot_sheriffing.md)
has been created to ensure the builds and tests stay green, so the perf
regression sheriff role is now entirely focused on performance.

**[Rotation calendar](https://calendar.google.com/calendar/embed?src=google.com_2fpmo740pd1unrui9d7cgpbg2k%40group.calendar.google.com)**

## Key Responsibilities

 * [Triage Regressions on the Perf Dashboard](#Triage-Regressions-on-the-Perf-Dashboard)
 * [Triaging Data Stoppage Alerts](#Triaging-Data-Stoppage-Alerts)
 * [Follow up on Performance Regressions](#Follow-up-on-Performance-Regressions)
 * [Give Feedback on our Infrastructure](#Give-Feedback-on-our-Infrastructure)

## Triage Regressions on the Perf Dashboard

Open the perf dashboard [alerts page](https://chromeperf.appspot.com/alerts).

In the upper right corner, **sign in with your Chromium account**. Signing in is
important in order to be able to kick off bisect jobs, and see data from
internal waterfalls.

Pick up **Chromium Perf Sheriff** from "Select an item ▼" drop down menu. There
are two tables of alerts that may be shown:

 * "Performance Alerts", which you should triage, and
 * "Data Stoppage Alerts", which you can ignore.

For either type of alert, if there are no currently pending alerts, then the
table won't be shown.

The list can be sorted by clicking on the column header. When you click on the
checkbox next to an alert, all the other alerts that occurred in the same
revision range will be highlighted.

Check the boxes next to the alerts you want to take a look at, and click the
"Graph" button. You'll be taken to a page with a table at the top listing all
the alerts that have an overlapping revision range with the one you chose, and
below it the dashboard shows graphs of all the alerts checked in that table.

1. **Look at the graph**.
    * If the alert appears to be **within the noise**, click on the red
      exclamation point icon for it in the graph and hit the "Report Invalid
      Alert" button.
    * If the alert appears to be **reverting a recent improvement**, click on
      the red exclamation point icon for it in the graph and hit the "Ignore
      Valid Alert" button.
    * If the alert is **visibly to the left or the right of the
      actual regression**, click on it and use the "nudge" menu to move it into
      place.
    * If there is a line labeled "ref" on the graph, that is the reference build.
      It's an older version of Chrome, used to help us sort out whether a change
      to the bot or test might have caused the graph to jump, rather than a real
      performance regression. If **the ref build moved at the same time as the
      alert**, click on the alert and hit the "Report Invalid Alert" button.
2. **Look at the other alerts** in the table to see if any should be grouped together.
   Note that the bisect will automatically dupe bugs if it finds they have the
   same culprit, so you don't need to be too aggressive about grouping alerts
   that might not be related. Some signs alerts should be grouped together:
    * If they're all in the same test suite
    * If they all regressed the same metric (a lot of commonality in the Test
      column)
3. **Triage the group of alerts**. Check all the alerts you believe are related,
  and press the triage button.
    * If one of the alerts already has a bug id, click "existing bug" and use
      that bug id.
    * Otherwise click "new bug". Be sure to cc the
      [test owner](http://go/perf-owners) on the bug.
4. **Look at the revision range** for the regression. You can see it in the
   tooltip on the graph. If you see any likely culprits, cc the authors on the
   bug.
5. **Optionally, kick off more bisects**. The perf dashboard will automatically
   kick off a bisect for each bug you file. But if you think the regression is
   much clearer on one platform, or a specific page of a page set, or you want
   to see a broader revision range feel free to click on the alert on that graph
   and kick off a bisect for it. There should be capacity to kick off as many
   bisects as you feel are necessary to investigate; [give feedback](#feedback)
   below if you feel that is not the case.

## Triaging Data Stoppage Alerts

Data stoppage alerts are listed on the
[perf dashboard alerts page](https://chromeperf.appspot.com/alerts). Whenever
the dashboard is monitoring a metric, and that metric stops sending data, an
alert is fired. Some of these alerts are expected:

   * When a telemetry benchmark is disabled, we get a data stoppage alert.
     Check the [code for the benchmark](https://code.google.com/p/chromium/codesearch#chromium/src/tools/perf/benchmarks/)
     to see if it has been disabled, and if so associate the alert with the
     bug for the disable.
   * When a bot has been turned down. These should be announced to
     perf-sheriffs@chromium.org, but if you can't find the bot on
     [the waterfall](https://uberchromegw.corp.google.com/i/chromium.perf/) and
     you didn't see the announcement, double check in the speed infra chat.
     Ideally these will be associated with the bug for the bot turndown, but
     it's okay to mark them invalid if you can't find the bug.
     You can check the
     [recipe](https://chromium.googlesource.com/chromium/tools/build/+/master/scripts/slave/recipe_modules/chromium_tests/chromium_perf.py)
     to find a corresponding bot name for waterfall with one for dashboard.

If there doesn't seem to be a valid reason for the alert, file a bug on it
using the perf dashboard, and cc [the owner](http://go/perf-owners). Then do
some diagnosis:

   * Look at the perf dashboard graph to see the last revision we got data for,
     and note that in the bug. Click on the `buildbot stdio` link in the tooltip
     to find the buildbot status page for the last good build, and increment
     the build number to get the first build with no data, and note that in the
     bug as well. Check for any changes to the test in the revision range.
   * Go to the buildbot status page of the bot which should be running the test.
     Is it running the test? If not, note that in the bug.
   * If it is running the test and the test is failing, diagnose as a test
     failure.
   * If it is running the test and the test is passing, check the `json.output`
     link on the buildbot status page for the test. This is the data the test
     sent to the perf dashboard. Are there null values? Sometimes it lists a
     reason as well. Please put your finding in the bug.

## Follow up on Performance Regressions

During your shift, you should try to follow up on each of the bugs you filed.
Once you've triaged all the alerts, check to see if the bisects have come back,
or if they failed. If the results came back, and a culprit was found, follow up
with the CL author. If the bisects failed to update the bug with results, please
file a bug on it (see [feedback](#feedback) links below).

Also during your shift, please spend any spare time driving down bugs from the
[regression backlog](http://go/triage-backlog). Treat these bugs as you would
your own -- investigate the regressions, find out what the next step should be,
and then move the bug along. Some possible next steps and questions to answer
are:

*   Should the bug be closed?
*   Are there questions that need to be answered?
*   Are there people that should be added to the CC list?
*   Is the correct owner assigned?

When a bug does need to be pinged, rather than adding a generic "ping", it's
much much more effective to include the username and action item.

You should aim to end your shift with an empty backlog, but it's important to
still advance each bug in a meaningful way.

After your shift, please try to follow up on the bugs you filed weekly. Kick off
new bisects if the previous ones failed, and if the bisect picks a likely
culprit follow up to ensure the CL author addresses the problem. If you are
certain that a specific CL caused a performance regression, and the author does
not have an immediate plan to address the problem, please revert the CL.

## Give Feedback on our Infrastructure

Perf regression sheriffs have their eyes on the perf dashboard and bisects
more than anyone else, and their feedback is invaluable for making sure these
tools are accurate and improving them. Please file bugs and feature requests
as you see them:

* **Perf Dashboard**: Please use the red "Report Issue" link in the navbar.
* **Perf Bisect/Trybots**: If a bisect is identifying the wrong CL as culprit
  or missing a clear culprit, or not reproducing what appears to be a clear
  regression, please link the comment the bisect bot posted on the bug at
  [go/bad-bisects](https://docs.google.com/spreadsheets/d/13PYIlRGE8eZzsrSocA3SR2LEHdzc8n9ORUoOE2vtO6I/edit#gid=0).
  The team triages these regularly. If you spot a really clear bug (bisect
  job red, bugs not being updated with bisect results) please file it in
  crbug with component `Tests>AutoBisect`. If a bisect problem is blocking a
  perf regression bug triage, **please file a new bug with component
  `Tests>AutoBisect` and block the regression bug on the bisect bug**. This
  makes it much easier for the team to triage, dupe, and close bugs on the
  infrastructure without affecting the state of the perf regression bugs.
* **Noisy Tests**: Please file a bug in crbug with component `Tests>Telemetry`
  and [cc the owner](http://go/perf-owners).
