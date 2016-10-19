// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.customtabs.test;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.support.customtabs.CustomTabsCallback;
import android.support.customtabs.CustomTabsClient;
import android.support.customtabs.CustomTabsIntent;
import android.support.customtabs.CustomTabsServiceConnection;
import android.support.customtabs.CustomTabsSession;
import android.util.Log;

/** Activity used to benchmark Custom Tabs PLT.
 */
public class MainActivity extends Activity {
    private static final String TAG = "CUSTOMTABSBENCH";
    private static final String DEFAULT_URL = "https://www.android.com";
    private static final String DEFAULT_PACKAGE = "com.google.android.apps.chrome";

    // Keep in sync with the same constants in CustomTabsConnection.
    private static final String DEBUG_OVERRIDE_KEY =
            "android.support.customtabs.maylaunchurl.DEBUG_OVERRIDE";
    private static final int NO_OVERRIDE = 0;
    private static final int NO_PRERENDERING = 1;
    private static final int PREFETCH_ONLY = 2;
    // Only for reporting.
    private static final int NO_STATE_PREFETCH = 3;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        processArguments(getIntent());
    }

    /** Process the arguments from the Intent extras.
     */
    private void processArguments(Intent intent) {
        String url = intent.getStringExtra("url");
        if (url == null) url = DEFAULT_URL;
        String packageName = intent.getStringExtra("package_name");
        if (packageName == null) packageName = DEFAULT_PACKAGE;
        boolean warmup = intent.getBooleanExtra("warmup", false);
        int delayToMayLaunchUrl = intent.getIntExtra("delay_to_may_launch_url", -1);
        int delayToLaunchUrl = intent.getIntExtra("delay_to_launch_url", -1);

        int speculationMode = 0;
        String speculationModeValue = intent.getStringExtra("speculation_mode");
        switch (speculationModeValue) {
            case "prerender":
                speculationMode = NO_OVERRIDE;
                break;
            case "disabled":
                speculationMode = NO_PRERENDERING;
                break;
            case "speculative_prefetch":
                speculationMode = PREFETCH_ONLY;
                break;
            case "no_state_prefetch":
                speculationMode = NO_STATE_PREFETCH;
                break;
            default:
                throw new IllegalArgumentException(
                        "Invalid prerender mode: " + speculationModeValue);
        }

        launchCustomTabs(
                packageName, url, warmup, speculationMode, delayToMayLaunchUrl, delayToLaunchUrl);
    }

    private static final class CustomCallback extends CustomTabsCallback {
        private final boolean mWarmup;
        private final int mSpeculationMode;
        private final int mDelayToMayLaunchUrl;
        private final int mDelayToLaunchUrl;
        private long mIntentSentMs = 0;
        private long mPageLoadStartedMs = 0;
        private long mPageLoadFinishedMs = 0;
        private long mFirstContentfulPaintMs = -1;
        private boolean mAlreadyLogged = false;

        public CustomCallback(boolean warmup, int speculationMode, int delayToMayLaunchUrl,
                int delayToLaunchUrl) {
            mWarmup = warmup;
            mSpeculationMode = speculationMode;
            mDelayToMayLaunchUrl = delayToMayLaunchUrl;
            mDelayToLaunchUrl = delayToLaunchUrl;
        }

        public void recordIntentHasBeenSent() {
            mIntentSentMs = SystemClock.elapsedRealtime();
        }

        @Override
        public void onNavigationEvent(int navigationEvent, Bundle extras) {
            switch (navigationEvent) {
                case CustomTabsCallback.NAVIGATION_STARTED:
                    mPageLoadStartedMs = SystemClock.elapsedRealtime();
                    break;
                case CustomTabsCallback.NAVIGATION_FINISHED:
                    mPageLoadFinishedMs = SystemClock.elapsedRealtime();
                    if (mIntentSentMs != 0 && mPageLoadStartedMs != 0) {
                        if (mFirstContentfulPaintMs != -1) {
                            logMetrics();
                        } else {
                            Handler handler = new Handler(Looper.getMainLooper());
                            handler.postDelayed(new Runnable() {
                                @Override
                                public void run() {
                                    logMetrics();
                                }
                            }, 3000);
                        }
                    }
                    break;
                default:
                    break;
            }
        }

        @Override
        public void extraCallback(String callbackName, Bundle args) {
            assert "NavigationMetrics".equals(callbackName);
            long value = args.getLong("firstContentfulPaint", -1);
            // Can be reported several times, only record the first one.
            if (mFirstContentfulPaintMs == -1) mFirstContentfulPaintMs = value;
            if (!mAlreadyLogged && mPageLoadFinishedMs != 0) logMetrics();
        }

        private void logMetrics() {
            if (mAlreadyLogged) return;
            String logLine = (mWarmup ? "1" : "0") + "," + mSpeculationMode + ","
                    + mDelayToMayLaunchUrl + "," + mDelayToLaunchUrl + "," + mIntentSentMs + ","
                    + mPageLoadStartedMs + "," + mPageLoadFinishedMs + ","
                    + mFirstContentfulPaintMs;
            Log.w(TAG, logLine);
            mAlreadyLogged = true;
        }
    }

    private void onCustomTabsServiceConnected(CustomTabsClient client, final Uri uri,
            final CustomCallback cb, boolean warmup, final int prerenderMode,
            int delayToMayLaunchUrl, final int delayToLaunchUrl) {
        final Handler handler = new Handler(Looper.getMainLooper());
        final CustomTabsSession session = client.newSession(cb);
        final CustomTabsIntent intent = (new CustomTabsIntent.Builder(session)).build();
        final Runnable launchRunnable = new Runnable() {
            @Override
            public void run() {
                intent.launchUrl(MainActivity.this, uri);
                cb.recordIntentHasBeenSent();
            }
        };
        Runnable mayLaunchRunnable = new Runnable() {
            @Override
            public void run() {
                Bundle extras = new Bundle();
                if (prerenderMode == NO_PRERENDERING) {
                    extras.putInt(DEBUG_OVERRIDE_KEY, NO_PRERENDERING);
                } else if (prerenderMode != NO_STATE_PREFETCH) {
                    extras.putInt(DEBUG_OVERRIDE_KEY, prerenderMode);
                }

                session.mayLaunchUrl(uri, extras, null);
                handler.postDelayed(launchRunnable, delayToLaunchUrl);
            }
        };

        if (warmup) client.warmup(0);
        if (delayToMayLaunchUrl != -1) {
            handler.postDelayed(mayLaunchRunnable, delayToMayLaunchUrl);
        } else {
            launchRunnable.run();
        }
    }

    private void launchCustomTabs(String packageName, String url, final boolean warmup,
            final int speculationMode, final int delayToMayLaunchUrl, final int delayToLaunchUrl) {
        final CustomCallback cb =
                new CustomCallback(warmup, speculationMode, delayToMayLaunchUrl, delayToLaunchUrl);
        final Uri uri = Uri.parse(url);
        CustomTabsClient.bindCustomTabsService(
                this, packageName, new CustomTabsServiceConnection() {
                    @Override
                    public void onCustomTabsServiceConnected(
                            ComponentName name, final CustomTabsClient client) {
                        MainActivity.this.onCustomTabsServiceConnected(client, uri, cb, warmup,
                                speculationMode, delayToMayLaunchUrl, delayToLaunchUrl);
                    }

                    @Override
                    public void onServiceDisconnected(ComponentName name) {}
                });
    }
}
