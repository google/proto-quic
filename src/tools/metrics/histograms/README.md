# Histogram Guidelines

This document gives the best practices on how to use histograms in code and how
to document the histograms for the dashboards.  There are three general types
of histograms: enumerated histograms, count histograms (for arbitrary numbers),
and sparse histograms (for anything when the precision is important over a wide
range and/or the range is not possible to specify a priori).

[TOC]

## Emitting to Histograms

### Directly Measure What You Want

Measure exactly what you want, whether that's time used for a function call,
number of bytes transmitted to fetch a page, number of items in a list, etc.
Do not assume you can calculate what you want from other histograms.  Most of
the ways to do this are incorrect.  For example, if you want to know the time
taken by a function that all it does is call two other functions, both of which
are have histogram logging, you might think you can simply add up those
the histograms for those functions to get the total time.  This is wrong.
If we knew which emissions came from which calls, we could pair them up and
derive the total time for the function.  However, histograms entries do not
come with timestamps--we pair them up appropriately.  If you simply add up the
two histograms to get the total histogram, you're implicitly assuming those
values are independent, which may not be the case.  Directly measure what you
care about; don't try to derive it from other data.

### Efficiency

In general, the histogram code is highly optimized.  Do not be concerned about
the processing cost of emitting to a histogram (unless you're using [sparse
histograms](#When-To-Use-Sparse-Histograms)).

### Enum Histograms

Enumerated histogram are most appropriate when you have a list of connected /
related states that should be analyzed jointly.  For example, the set of
actions that can be done on the New Tab Page (use the omnibox, click a most
visited tile, click a bookmark, etc.) would make a good enumerated histogram.
If the total count of your histogram (i.e. the sum across all buckets) is
something meaningful--as it is in this example--that is generally a good sign.
However, the total count does not have to be meaningful for an enum histogram
to still be the right choice.

You may append to your enum if the possible states/actions grows.  However, you
should not reorder, renumber, or otherwise reuse existing values.  As such,
please put this warning by the enum definition:
```
// These values are written to logs.  New enum values can be added, but existing
// enums must never be renumbered or deleted and reused.
enum NEW_TAB_PAGE_ACTION {
  USE_OMNIBOX = 0,
  CLICK_TILE = 1,
  OPEN_BOOKMARK = 2,
  NEW_TAB_PAGE_ACTION_MAX
};
```

Also, please explicitly set enum values `= 0`, `= 1`, `= 2`, etc.  This makes
clearer that the actual values are important.  In addition, it helps confirm
the values align between the enum definition and
[histograms.xml](./histograms.xml).  If a "max" value is included it
should not include an explicit value.

If your enum histogram has a catch-all / miscellaneous bucket, put that bucket
first (`= 0`).  This will make the bucket easy to find on the dashboard if
later you add additional buckets to your histogram.

### Count Histograms

[histogram_macros.h](https://cs.chromium.org/chromium/src/base/metrics/histogram_macros.h)
provides macros for some common count types such as memory or elapsed time, in
addition to general count macros.  These have reasonable default values; you
will not often need to choose number of buckets or histogram min.  You still
will need to choose the histogram max (use the advice below).

If none of the default macros work well for you, please thoughtfully choose
a min, max, and bucket count for your histogram using the advice below.

#### Count Histograms: Choosing Min and Max

For histogram max, choose a value so that very few emission to the histogram
will exceed the max.  If many emissions hit the max, it can be difficult to
compute statistics such as average.  One rule of thumb is at most 1% of samples
should be in the overflow bucket.  This allows analysis of the 99th percentile.
Err on the side of too large a range versus too short a range.  (Remember that
if you choose poorly, you'll have to wait for another release cycle to fix it.)

For histogram min, if you care about all possible values (zero and above),
choose a min of 1.  (All histograms have an underflow bucket; emitted zeros
will go there.  That's why a min of 1 is appropriate.)  Otherwise, choose the
min appropriate for your particular situation.

#### Count Histograms: Choosing Number of Buckets

Choose the smallest number of buckets that will get you the granularity you
need.  By default count histograms bucket sizes scale exponentially so you can
get fine granularity when the numbers are small yet still reasonable resolution
for larger numbers.  The macros default to 50 buckets (or 100 buckets for
histograms with wide ranges) which is appropriate for most purposes.  Because
histograms pre-allocate all the buckets, the number of buckets selected
directly dictate how much memory is used.  Do not exceed 100 buckets without
good reason (and consider whether [sparse histograms](#When-To-Use-Sparse-
Histograms) might work better for you in that case--they do not pre- allocate
their buckets).

### Local Histograms

Histograms can be added via [Local macros](https://codesearch.chromium.org/chromium/src/base/metrics/histogram_macros_local.h). These will still record
locally, but will not be uploaded to UMA and will therefore not be available
for analysis. This can be useful for metrics only needed for local debugging.
We don't recommend using local histograms outside of that scenario.

### Multidimensional Histograms

It is common to be interested in logging multidimensional data - where multiple
pieces of information need to be logged together. For example, a developer may
be interested in the counts of features X and Y based on whether a user is in
state A or B. In this case, they want to know the count of X under state A,
as well as the other three permutations.

There is no general purpose solution for this type of analysis. We suggest
using the workaround of using an enum of length MxN, where you log each unique
pair {state, feature} as a separate entry in the same enum. If this causes a
large explosion in data (i.e. >100 enum entries), a [sparse histogram](#When-To-Use-Sparse-Histograms) may be appropriate. If you are unsure of the best way to proceed, please contact someone from the OWNERS file.

### Testing

Test your histograms using `chrome://histograms`.  Make sure they're being
emitted to when you expect and not emitted to at other times. Also check that
the values emitted to are correct.  Finally, for count histograms, make sure
that buckets capture enough precision for your needs over the range.

### Revising Histograms

If you're changing the semantics of a histogram (when it's emitted, what
buckets mean, etc.), make it into a new histogram with a new name.  Otherwise
the "Everything" view on the dashboard will be mixing two different
interpretations of the data and make no sense.

### Deleting Histograms

Please delete the code that emits to histograms that are no longer needed.
Histograms take up memory.  Cleaning up histograms that you no longer care about
is good!  But see the note below on [Deleting Histogram Entries](#Deleting-Histogram-Entries).

## Documenting Histograms

### Add Histogram and Documentation in the Same Changelist

If possible, please add the [histograms.xml](./histograms.xml) description in
the same changelist in which you add the histogram-emitting code.  This has
several benefits.  One, it sometimes happens that the
[histograms.xml](./histograms.xml) reviewer has questions or concerns about the
histogram description that reveal problems with interpretation of the data and
call for a different recording strategy.  Two, it allows the histogram reviewer
to easily review the emission code to see if it comports with these best
practices, and to look for other errors.

### Understandable to Everyone

Histogram descriptions should be roughly understandable to someone not familiar
with your feature.  Please add a sentence or two of background if necessary.

It is good practice to note caveats associated with your histogram in this
section, such as which platforms are supported (if the set of supported
platforms is surprising).  E.g., a desktop feature that happens not to be logged
on Mac.

### State When It Is Recorded

Histogram descriptions should clearly state when the histogram is emitted
(profile open? network request received? etc.).

### Owners

Histograms need to be owned by a person or set of people. These indicate who
the current experts on this metric are. Being the owner means you are
responsible for answering questions about the metric, handling the maintenance
if there are functional changes, and deprecating the metric if it outlives its
usefulness. The owners should be added in the original histogram description.
If you are using a metric heavily and understand it intimately, feel free to
add yourself as an owner. @chromium.org email addresses are preferred.


### Deleting Histogram Entries

Do not delete histograms from [histograms.xml](./histograms.xml).  Instead, mark
unused histograms as obsolete, annotating them with the associated date or
milestone in the obsolete tag entry.  If your histogram is being replaced by a
new version, we suggest noting that in the previous histogram's description.

Deleting histogram entries would be bad if someone to accidentally reused your
old histogram name and thereby corrupts new data with whatever old data is still
coming in.  It's also useful to keep obsolete histogram descriptions in
[histograms.xml](./histograms.xml) -- that way, if someone is searching for a
histogram to answer a particular question, they can learn if there was a
histogram at some point that did so even if it isn't active now.

## When To Use Sparse Histograms

Sparse histograms are well suited for recording counts of exact sample values
that are sparsely distributed over a large range.

The implementation uses a lock and a map, whereas other histogram types use a
vector and no lock. It is thus more costly to add values to, and each value
stored has more overhead, compared to the other histogram types. However it
may be more efficient in memory if the total number of sample values is small
compared to the range of their values.

For more information, see [sparse_histograms.h](https://cs.chromium.org/chromium/src/base/metrics/sparse_histogram.h).
