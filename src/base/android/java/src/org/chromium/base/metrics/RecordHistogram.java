// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base.metrics;

import org.chromium.base.VisibleForTesting;
import org.chromium.base.annotations.JNINamespace;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Java API for recording UMA histograms.
 *
 * Internally, histograms objects are cached on the Java side by their pointer
 * values (converted to long). This is safe to do because C++ Histogram objects
 * are never freed. Caching them on the Java side prevents needing to do costly
 * Java String to C++ string conversions on the C++ side during lookup.
 *
 * Note: the JNI calls are relatively costly - avoid calling these methods in performance-critical
 * code.
 */
@JNINamespace("base::android")
public class RecordHistogram {
    private static boolean sIsDisabledForTests = false;
    private static Map<String, Long> sCache =
            Collections.synchronizedMap(new HashMap<String, Long>());

    /**
     * Tests may not have native initialized, so they may need to disable metrics.
     */
    @VisibleForTesting
    public static void disableForTests() {
        sIsDisabledForTests = true;
    }

    private static long getCachedHistogramKey(String name) {
        Long key = sCache.get(name);
        // Note: If key is null, we don't have it cached. In that case, pass 0
        // to the native code, which gets converted to a null histogram pointer
        // which will cause the native code to look up the object on the native
        // side.
        return (key == null ? 0 : key);
    }

    /**
     * Records a sample in a boolean UMA histogram of the given name. Boolean histogram has two
     * buckets, corresponding to success (true) and failure (false). This is the Java equivalent of
     * the UMA_HISTOGRAM_BOOLEAN C++ macro.
     * @param name name of the histogram
     * @param sample sample to be recorded, either true or false
     */
    public static void recordBooleanHistogram(String name, boolean sample) {
        if (sIsDisabledForTests) return;
        long key = getCachedHistogramKey(name);
        long result = nativeRecordBooleanHistogram(name, key, sample);
        if (result != key) sCache.put(name, result);
    }

    /**
     * Records a sample in an enumerated histogram of the given name and boundary. Note that
     * |boundary| identifies the histogram - it should be the same at every invocation. This is the
     * Java equivalent of the UMA_HISTOGRAM_ENUMERATION C++ macro.
     * @param name name of the histogram
     * @param sample sample to be recorded, at least 0 and at most |boundary| - 1
     * @param boundary upper bound for legal sample values - all sample values have to be strictly
     *        lower than |boundary|
     */
    public static void recordEnumeratedHistogram(String name, int sample, int boundary) {
        if (sIsDisabledForTests) return;
        long key = getCachedHistogramKey(name);
        long result = nativeRecordEnumeratedHistogram(name, key, sample, boundary);
        if (result != key) sCache.put(name, result);
    }

    /**
     * Records a sample in a count histogram. This is the Java equivalent of the
     * UMA_HISTOGRAM_COUNTS C++ macro.
     * @param name name of the histogram
     * @param sample sample to be recorded, at least 1 and at most 999999
     */
    public static void recordCountHistogram(String name, int sample) {
        recordCustomCountHistogram(name, sample, 1, 1000000, 50);
    }

    /**
     * Records a sample in a count histogram. This is the Java equivalent of the
     * UMA_HISTOGRAM_COUNTS_100 C++ macro.
     * @param name name of the histogram
     * @param sample sample to be recorded, at least 1 and at most 99
     */
    public static void recordCount100Histogram(String name, int sample) {
        recordCustomCountHistogram(name, sample, 1, 100, 50);
    }

    /**
     * Records a sample in a count histogram. This is the Java equivalent of the
     * UMA_HISTOGRAM_COUNTS_1000 C++ macro.
     * @param name name of the histogram
     * @param sample sample to be recorded, at least 1 and at most 999
     */
    public static void recordCount1000Histogram(String name, int sample) {
        recordCustomCountHistogram(name, sample, 1, 1000, 50);
    }

    /**
     * Records a sample in a count histogram. This is the Java equivalent of the
     * UMA_HISTOGRAM_CUSTOM_COUNTS C++ macro.
     * @param name name of the histogram
     * @param sample sample to be recorded, at least |min| and at most |max| - 1
     * @param min lower bound for expected sample values
     * @param max upper bounds for expected sample values
     * @param numBuckets the number of buckets
     */
    public static void recordCustomCountHistogram(
            String name, int sample, int min, int max, int numBuckets) {
        if (sIsDisabledForTests) return;
        long key = getCachedHistogramKey(name);
        long result = nativeRecordCustomCountHistogram(name, key, sample, min, max, numBuckets);
        if (result != key) sCache.put(name, result);
    }

    /**
     * Records a sample in a linear histogram. This is the Java equivalent for using
     * base::LinearHistogram.
     * @param name name of the histogram
     * @param sample sample to be recorded, at least |min| and at most |max| - 1.
     * @param min lower bound for expected sample values, should be at least 1.
     * @param max upper bounds for expected sample values
     * @param numBuckets the number of buckets
     */
    public static void recordLinearCountHistogram(
            String name, int sample, int min, int max, int numBuckets) {
        if (sIsDisabledForTests) return;
        long key = getCachedHistogramKey(name);
        long result = nativeRecordLinearCountHistogram(name, key, sample, min, max, numBuckets);
        if (result != key) sCache.put(name, result);
    }

    /**
     * Records a sample in a percentage histogram. This is the Java equivalent of the
     * UMA_HISTOGRAM_PERCENTAGE C++ macro.
     * @param name name of the histogram
     * @param sample sample to be recorded, at least 0 and at most 100.
     */
    public static void recordPercentageHistogram(String name, int sample) {
        if (sIsDisabledForTests) return;
        long key = getCachedHistogramKey(name);
        long result = nativeRecordEnumeratedHistogram(name, key, sample, 101);
        if (result != key) sCache.put(name, result);
    }

    /**
    * Records a sparse histogram. This is the Java equivalent of UMA_HISTOGRAM_SPARSE_SLOWLY.
    * @param name name of the histogram
    * @param sample sample to be recorded. All values of |sample| are valid, including negative
    *        values.
    */
    public static void recordSparseSlowlyHistogram(String name, int sample) {
        if (sIsDisabledForTests) return;
        long key = getCachedHistogramKey(name);
        long result = nativeRecordSparseHistogram(name, key, sample);
        if (result != key) sCache.put(name, result);
    }

    /**
     * Records a sample in a histogram of times. Useful for recording short durations. This is the
     * Java equivalent of the UMA_HISTOGRAM_TIMES C++ macro.
     * @param name name of the histogram
     * @param duration duration to be recorded
     * @param timeUnit the unit of the duration argument
     */
    public static void recordTimesHistogram(String name, long duration, TimeUnit timeUnit) {
        recordCustomTimesHistogramMilliseconds(
                name, timeUnit.toMillis(duration), 1, TimeUnit.SECONDS.toMillis(10), 50);
    }

    /**
     * Records a sample in a histogram of times. Useful for recording medium durations. This is the
     * Java equivalent of the UMA_HISTOGRAM_MEDIUM_TIMES C++ macro.
     * @param name name of the histogram
     * @param duration duration to be recorded
     * @param timeUnit the unit of the duration argument
     */
    public static void recordMediumTimesHistogram(String name, long duration, TimeUnit timeUnit) {
        recordCustomTimesHistogramMilliseconds(
                name, timeUnit.toMillis(duration), 10, TimeUnit.MINUTES.toMillis(3), 50);
    }

    /**
     * Records a sample in a histogram of times. Useful for recording long durations. This is the
     * Java equivalent of the UMA_HISTOGRAM_LONG_TIMES C++ macro.
     * @param name name of the histogram
     * @param duration duration to be recorded
     * @param timeUnit the unit of the duration argument
     */
    public static void recordLongTimesHistogram(String name, long duration, TimeUnit timeUnit) {
        recordCustomTimesHistogramMilliseconds(
                name, timeUnit.toMillis(duration), 1, TimeUnit.HOURS.toMillis(1), 50);
    }

    /**
     * Records a sample in a histogram of times with custom buckets. This is the Java equivalent of
     * the UMA_HISTOGRAM_CUSTOM_TIMES C++ macro.
     * @param name name of the histogram
     * @param duration duration to be recorded
     * @param min the minimum bucket value
     * @param max the maximum bucket value
     * @param timeUnit the unit of the duration, min, and max arguments
     * @param numBuckets the number of buckets
     */
    public static void recordCustomTimesHistogram(
            String name, long duration, long min, long max, TimeUnit timeUnit, int numBuckets) {
        recordCustomTimesHistogramMilliseconds(name, timeUnit.toMillis(duration),
                timeUnit.toMillis(min), timeUnit.toMillis(max), numBuckets);
    }

    private static int clampToInt(long value) {
        if (value > Integer.MAX_VALUE) return Integer.MAX_VALUE;
        // Note: Clamping to MIN_VALUE rather than 0, to let base/ histograms code
        // do its own handling of negative values in the future.
        if (value < Integer.MIN_VALUE) return Integer.MIN_VALUE;
        return (int) value;
    }

    private static void recordCustomTimesHistogramMilliseconds(
            String name, long duration, long min, long max, int numBuckets) {
        if (sIsDisabledForTests) return;
        long key = getCachedHistogramKey(name);
        // Note: Duration, min and max are clamped to int here because that's what's expected by
        // the native histograms API. Callers of these functions still pass longs because that's
        // the types returned by TimeUnit and System.currentTimeMillis() APIs, from which these
        // values come.
        long result = nativeRecordCustomTimesHistogramMilliseconds(
                name, key, clampToInt(duration), clampToInt(min), clampToInt(max), numBuckets);
        if (result != key) sCache.put(name, result);
    }

    /**
     * Returns the number of samples recorded in the given bucket of the given histogram.
     * @param name name of the histogram to look up
     * @param sample the bucket containing this sample value will be looked up
     */
    @VisibleForTesting
    public static int getHistogramValueCountForTesting(String name, int sample) {
        return nativeGetHistogramValueCountForTesting(name, sample);
    }

    /**
     * Initializes the metrics system.
     */
    public static void initialize() {
        if (sIsDisabledForTests) return;
        nativeInitialize();
    }

    private static native long nativeRecordCustomTimesHistogramMilliseconds(
            String name, long key, int duration, int min, int max, int numBuckets);

    private static native long nativeRecordBooleanHistogram(String name, long key, boolean sample);
    private static native long nativeRecordEnumeratedHistogram(
            String name, long key, int sample, int boundary);
    private static native long nativeRecordCustomCountHistogram(
            String name, long key, int sample, int min, int max, int numBuckets);
    private static native long nativeRecordLinearCountHistogram(
            String name, long key, int sample, int min, int max, int numBuckets);
    private static native long nativeRecordSparseHistogram(String name, long key, int sample);

    private static native int nativeGetHistogramValueCountForTesting(String name, int sample);
    private static native void nativeInitialize();
}
