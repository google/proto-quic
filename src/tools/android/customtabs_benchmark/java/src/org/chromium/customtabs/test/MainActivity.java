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
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.RadioButton;

/** Activity used to benchmark Custom Tabs PLT.
 *
 * This activity contains benchmark code for two modes:
 * 1. Comparison between a basic use of Custom Tabs and a basic use of WebView.
 * 2. Custom Tabs benchmarking under various scenarios.
 *
 * The two modes are not merged into one as the metrics we can extract in the two cases
 * are constrained for the first one by what WebView provides.
 */
public class MainActivity extends Activity implements View.OnClickListener {
    static final String TAG = "CUSTOMTABSBENCH";
    private static final String DEFAULT_URL = "https://www.android.com";
    private static final String DEFAULT_PACKAGE = "com.google.android.apps.chrome";
    private static final int NONE = -1;
    // Common key between the benchmark modes.
    private static final String URL_KEY = "url";

    // Keys for the WebView / Custom Tabs comparison.
    static final String INTENT_SENT_EXTRA = "intent_sent_ms";
    private static final String USE_WEBVIEW_KEY = "use_webview";
    private static final String WARMUP_KEY = "warmup";

    // Keep in sync with the same constants in CustomTabsConnection.
    private static final String DEBUG_OVERRIDE_KEY =
            "android.support.customtabs.maylaunchurl.DEBUG_OVERRIDE";
    private static final int NO_OVERRIDE = 0;
    private static final int NO_PRERENDERING = 1;
    private static final int PREFETCH_ONLY = 2;
    // Only for reporting.
    private static final int NO_STATE_PREFETCH = 3;

    private final Handler mHandler = new Handler(Looper.getMainLooper());

    private EditText mUrlEditText;
    private RadioButton mChromeRadioButton;
    private RadioButton mWebViewRadioButton;
    private CheckBox mWarmupCheckbox;
    private long mIntentSentMs;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        final Intent intent = getIntent();

        setUpUi();

        // Automated mode, 1s later to leave time for the app to settle.
        if (intent.getStringExtra(URL_KEY) != null) {
            mHandler.postDelayed(new Runnable() {
                @Override
                public void run() {
                    processArguments(intent);
                }
            }, 1000);
        }
    }

    /** Displays the UI and registers the click listeners. */
    private void setUpUi() {
        setContentView(R.layout.main);

        mUrlEditText = (EditText) findViewById(R.id.url_text);
        mChromeRadioButton = (RadioButton) findViewById(R.id.radio_chrome);
        mWebViewRadioButton = (RadioButton) findViewById(R.id.radio_webview);
        mWarmupCheckbox = (CheckBox) findViewById(R.id.warmup_checkbox);
        Button goButton = (Button) findViewById(R.id.go_button);

        mUrlEditText.setOnClickListener(this);
        mChromeRadioButton.setOnClickListener(this);
        mWebViewRadioButton.setOnClickListener(this);
        mWarmupCheckbox.setOnClickListener(this);
        goButton.setOnClickListener(this);
    }

    @Override
    public void onClick(View v) {
        int id = v.getId();

        boolean warmup = mWarmupCheckbox.isChecked();
        boolean useChrome = mChromeRadioButton.isChecked();
        boolean useWebView = mWebViewRadioButton.isChecked();
        String url = mUrlEditText.getText().toString();

        if (id == R.id.go_button) {
            customTabsWebViewBenchmark(url, useChrome, useWebView, warmup);
        }
    }

    /** Routes to either of the benchmark modes. */
    private void processArguments(Intent intent) {
        if (intent.hasExtra(USE_WEBVIEW_KEY)) {
            startCustomTabsWebViewBenchmark(intent);
        } else {
            startCustomTabsBenchmark(intent);
        }
    }

    /** Start the CustomTabs / WebView comparison benchmark.
     *
     * NOTE: Methods below are for the first benchmark mode.
     */
    private void startCustomTabsWebViewBenchmark(Intent intent) {
        Bundle extras = intent.getExtras();
        String url = extras.getString(URL_KEY);
        boolean useWebView = extras.getBoolean(USE_WEBVIEW_KEY);
        boolean useChrome = !useWebView;
        boolean warmup = extras.getBoolean(WARMUP_KEY);
        customTabsWebViewBenchmark(url, useChrome, useWebView, warmup);
    }

    /** Start the CustomTabs / WebView comparison benchmark. */
    private void customTabsWebViewBenchmark(
            String url, boolean useChrome, boolean useWebView, boolean warmup) {
        if (useChrome) {
            launchChrome(url, warmup);
        } else {
            assert useWebView;
            launchWebView(url);
        }
    }

    private void launchWebView(String url) {
        Intent intent = new Intent();
        intent.setData(Uri.parse(url));
        intent.setClass(this, WebViewActivity.class);
        intent.putExtra(INTENT_SENT_EXTRA, now());
        startActivity(intent);
    }

    private void launchChrome(final String url, final boolean warmup) {
        CustomTabsServiceConnection connection = new CustomTabsServiceConnection() {
            @Override
            public void onCustomTabsServiceConnected(ComponentName name, CustomTabsClient client) {
                launchChromeIntent(url, warmup, client);
            }

            @Override
            public void onServiceDisconnected(ComponentName name) {}
        };
        CustomTabsClient.bindCustomTabsService(this, DEFAULT_PACKAGE, connection);
    }

    private void launchChromeIntent(String url, boolean warmup, CustomTabsClient client) {
        CustomTabsCallback callback = new CustomTabsCallback() {
            private long mNavigationStartOffsetMs;

            @Override
            public void onNavigationEvent(int navigationEvent, Bundle extras) {
                long offsetMs = now() - mIntentSentMs;
                switch (navigationEvent) {
                    case CustomTabsCallback.NAVIGATION_STARTED:
                        mNavigationStartOffsetMs = offsetMs;
                        Log.w(TAG, "navigationStarted = " + offsetMs);
                        break;
                    case CustomTabsCallback.NAVIGATION_FINISHED:
                        Log.w(TAG, "navigationFinished = " + offsetMs);
                        Log.w(TAG, "CHROME," + mNavigationStartOffsetMs + "," + offsetMs);
                        break;
                    default:
                        break;
                }
            }
        };
        CustomTabsSession session = client.newSession(callback);
        final CustomTabsIntent customTabsIntent = new CustomTabsIntent.Builder(session).build();
        final Uri uri = Uri.parse(url);

        if (warmup) {
            client.warmup(0);
            mHandler.postDelayed(new Runnable() {
                @Override
                public void run() {
                    mIntentSentMs = now();
                    customTabsIntent.launchUrl(MainActivity.this, uri);
                }
            }, 3000);
        } else {
            mIntentSentMs = now();
            customTabsIntent.launchUrl(MainActivity.this, uri);
        }
    }

    static long now() {
        return System.currentTimeMillis();
    }

    /** Start the second benchmark mode.
     *
     * NOTE: Methods below are for the second mode.
     */
    private void startCustomTabsBenchmark(Intent intent) {
        String url = intent.getStringExtra(URL_KEY);
        if (url == null) url = DEFAULT_URL;
        String packageName = intent.getStringExtra("package_name");
        if (packageName == null) packageName = DEFAULT_PACKAGE;
        boolean warmup = intent.getBooleanExtra("warmup", false);
        int delayToMayLaunchUrl = intent.getIntExtra("delay_to_may_launch_url", NONE);
        int delayToLaunchUrl = intent.getIntExtra("delay_to_launch_url", NONE);

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

        int timeoutSeconds = intent.getIntExtra("timeout", NONE);

        launchCustomTabs(packageName, url, warmup, speculationMode, delayToMayLaunchUrl,
                delayToLaunchUrl, timeoutSeconds);
    }

    private final class CustomCallback extends CustomTabsCallback {
        private final boolean mWarmup;
        private final int mSpeculationMode;
        private final int mDelayToMayLaunchUrl;
        private final int mDelayToLaunchUrl;
        private long mIntentSentMs = NONE;
        private long mPageLoadStartedMs = NONE;
        private long mPageLoadFinishedMs = NONE;
        private long mFirstContentfulPaintMs = NONE;

        public CustomCallback(boolean warmup, int speculationMode, int delayToMayLaunchUrl,
                int delayToLaunchUrl) {
            mWarmup = warmup;
            mSpeculationMode = speculationMode;
            mDelayToMayLaunchUrl = delayToMayLaunchUrl;
            mDelayToLaunchUrl = delayToLaunchUrl;
        }

        public void recordIntentHasBeenSent() {
            mIntentSentMs = SystemClock.uptimeMillis();
        }

        @Override
        public void onNavigationEvent(int navigationEvent, Bundle extras) {
            switch (navigationEvent) {
                case CustomTabsCallback.NAVIGATION_STARTED:
                    mPageLoadStartedMs = SystemClock.uptimeMillis();
                    break;
                case CustomTabsCallback.NAVIGATION_FINISHED:
                    mPageLoadFinishedMs = SystemClock.uptimeMillis();
                    break;
                default:
                    break;
            }
            if (allSet()) logMetricsAndFinish();
        }

        @Override
        public void extraCallback(String callbackName, Bundle args) {
            assert "NavigationMetrics".equals(callbackName);
            long firstPaintMs = args.getLong("firstContentfulPaint", NONE);
            long navigationStartMs = args.getLong("navigationStart", NONE);
            if (firstPaintMs == NONE || navigationStartMs == NONE) return;
            // Can be reported several times, only record the first one.
            if (mFirstContentfulPaintMs == NONE) {
                mFirstContentfulPaintMs = navigationStartMs + firstPaintMs;
            }
            if (allSet()) logMetricsAndFinish();
        }

        private boolean allSet() {
            return mIntentSentMs != NONE && mPageLoadStartedMs != NONE
                    && mFirstContentfulPaintMs != NONE && mPageLoadFinishedMs != NONE;
        }

        /** Outputs the available metrics, and die. Unavalaible metrics are set to -1. */
        private void logMetricsAndFinish() {
            String logLine = (mWarmup ? "1" : "0") + "," + mSpeculationMode + ","
                    + mDelayToMayLaunchUrl + "," + mDelayToLaunchUrl + "," + mIntentSentMs + ","
                    + mPageLoadStartedMs + "," + mPageLoadFinishedMs + ","
                    + mFirstContentfulPaintMs;
            Log.w(TAG, logLine);
            MainActivity.this.finish();
        }

        /** Same as {@link logMetricsAndFinish()} with a set delay in ms. */
        public void logMetricsAndFinishDelayed(int delayMs) {
            mHandler.postDelayed(new Runnable() {
                @Override
                public void run() {
                    logMetricsAndFinish();
                }
            }, delayMs);
        }
    }

    private void onCustomTabsServiceConnected(CustomTabsClient client, final Uri uri,
            final CustomCallback cb, boolean warmup, final int prerenderMode,
            int delayToMayLaunchUrl, final int delayToLaunchUrl, final int timeoutSeconds) {
        final CustomTabsSession session = client.newSession(cb);
        final CustomTabsIntent intent = (new CustomTabsIntent.Builder(session)).build();
        final Runnable launchRunnable = new Runnable() {
            @Override
            public void run() {
                intent.launchUrl(MainActivity.this, uri);
                cb.recordIntentHasBeenSent();
                if (timeoutSeconds != NONE) cb.logMetricsAndFinishDelayed(timeoutSeconds * 1000);
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
                mHandler.postDelayed(launchRunnable, delayToLaunchUrl);
            }
        };

        if (warmup) client.warmup(0);
        if (delayToMayLaunchUrl != NONE) {
            mHandler.postDelayed(mayLaunchRunnable, delayToMayLaunchUrl);
        } else {
            mHandler.postDelayed(launchRunnable, delayToLaunchUrl);
        }
    }

    private void launchCustomTabs(String packageName, String url, final boolean warmup,
            final int speculationMode, final int delayToMayLaunchUrl, final int delayToLaunchUrl,
            final int timeoutSeconds) {
        final CustomCallback cb =
                new CustomCallback(warmup, speculationMode, delayToMayLaunchUrl, delayToLaunchUrl);
        final Uri uri = Uri.parse(url);
        CustomTabsClient.bindCustomTabsService(
                this, packageName, new CustomTabsServiceConnection() {
                    @Override
                    public void onCustomTabsServiceConnected(
                            ComponentName name, final CustomTabsClient client) {
                        MainActivity.this.onCustomTabsServiceConnected(client, uri, cb, warmup,
                                speculationMode, delayToMayLaunchUrl, delayToLaunchUrl,
                                timeoutSeconds);
                    }

                    @Override
                    public void onServiceDisconnected(ComponentName name) {}
                });
    }
}
