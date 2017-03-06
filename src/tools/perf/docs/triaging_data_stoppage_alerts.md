# Triaging Data Stoppage Alerts

## What is a data stoppage alert?
A data stoppage alert is a new type of alert on the perf dashboard. Instead of a
performance regression, it indicates that the dashboard is no longer receiving
data for the given monitored test. A bug created from a data stoppage alert has
a subject starting with **“No data received for…”**.

## How to triage data stoppage alerts

### Check if the alert is recovered.
Look at the graph and see if there are new points, if so, mark the alert
**ignored**.

### File a bug
Use the triage dialog to file a bug about the failure, and track your
investigation. Cc the owner of the benchmark from
[go/chrome-benchmarks](http://goto.google.com/chrome-benchmarks).

### Get the logs
Each alert has a debug button at the right-hand side of the table. It tries to
automatically find the last successful build and the first failed build. To get
the logs:
  * First try the *"Logs"* link from *"Next revison built"* (this should be the
    first failed revision). Sometimes this can't be generated properly, so it
    may not work.
  * Next try the *"Buildbot status page"* link from *"Next revision built"*.
    This should take you to the next build. **If this page 404s, it's possible
    the builder was taken down.** Check the waterfall.

Once you have the logs, put the link in the bug and also paste relevant snippets
about the failure (error logs) in the bug.

### Check for suspicious changes.
It has a link to *"View commit log from rXXX to rYYY"*, click the link to view
CLs in the range. Look through the range for test disables, telemetry/catapult
changes, and changes to the code under test. If you see a CL that looks like a
likely culprit, cc the author in the bug.

### Kick off a bisect.
If the test is failing on the *"Next revision built"*, bisect may be able to
narrow down the culprit. Go to the graph, click a data point, and click the
bisect button in the tooltip. **You'll need to change the values for return_code
bisect as follows**:
  * **Bug ID**: Make sure to fill in the ID of the bug you just filed.
    Otherwise the bisect will not update it.
  * **Earlier revision**: Change this to the *"Last revision uploaded"* from the
    debug button dialog.
  * **Later revision**: Change this to the *"Next revision built"* from the
    debug button dialog.
  * **Bisect mode**: Change this to **return_code**
