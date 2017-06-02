// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base.test.util;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import android.app.Instrumentation;
import android.content.res.Configuration;
import android.os.Build;
import android.support.test.InstrumentationRegistry;
import android.support.test.uiautomator.UiDevice;

import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

import java.io.File;
import java.util.Locale;

/**
 * Rule for taking screen shots within tests. Screenshots are saved as UiCapture/<test class>/<test
 * name>/<shot name>.png A simple example:
 *
 * <pre>
 * {
 *     &#64;code
 *
 *     &#64;RunWith(ChromeJUnit4ClassRunner.class)
 *     &#64;CommandLineFlags.Add({ChromeSwitches.DISABLE_FIRST_RUN_EXPERIENCE})
 *     &#64;Restriction(RESTRICTION_TYPE_PHONE) // Tab switcher button only exists on phones.
 *     public class ExampleUiCaptureTest {
 *         &#64;Rule
 *         public ChromeActivityTestRule<ChromeTabbedActivity> mActivityTestRule =
 *                 new ChromeActivityTestRule<>(ChromeTabbedActivity.class);
 *
 *         &#64;Rule
 *         public ScreenShooter mScreenShooter = new ScreenShooter();
 *
 *         &#64;Before
 *         public void setUp() throws InterruptedException {
 *             mActivityTestRule.startMainActivityFromLauncher();
 *         }
 *
 *         // Capture the New Tab Page and the tab switcher.
 *         &#64;Test
 *         &#64;SmallTest
 *         public void testCaptureTabSwitcher() throws IOException, InterruptedException {
 *             mScreenShooter.shoot("NTP");
 *             Espresso.onView(ViewMatchers.withId(R.id.tab_switcher_button))
 *                     .perform(ViewActions.click());
 *             mScreenShooter.shoot("Tab_switcher");
 *         }
 *     }
 * }
 * </pre>
 */
public class ScreenShooter extends TestWatcher {
    private static final String SCREENSHOT_DIR =
            "org.chromium.base.test.util.Screenshooter.ScreenshotDir";
    private final Instrumentation mInstrumentation;
    private final UiDevice mDevice;
    private final String mBaseDir;
    private final String mModel;
    private File mDir;

    public ScreenShooter() {
        mInstrumentation = InstrumentationRegistry.getInstrumentation();
        mDevice = UiDevice.getInstance(mInstrumentation);
        mBaseDir = InstrumentationRegistry.getArguments().getString(SCREENSHOT_DIR);
        mModel = getModelName();
    }

    @Override
    protected void starting(Description d) {
        File classDir = new File(mBaseDir, d.getClassName());
        mDir = new File(classDir, d.getMethodName());
        assertTrue("Create screenshot directory", mDir.mkdirs());
    }

    /**
     * Take a screen shot and save it to a file.
     *
     * @param shotName The name of this particular screenshot within this test. This will be used to
     *            name the image file.
     */
    public void shoot(String shotName) {
        assertNotNull("ScreenShooter rule initialized", mDir);
        assertTrue("Screenshot " + shotName,
                mDevice.takeScreenshot(new File(mDir, imageName(shotName))));
    }

    private String getModelName() {
        String model = Build.MODEL.replace(' ', '_');
        // Emulator model names are "SDK_built_for_x86" or similar, so use something more useful
        if (model.toUpperCase(Locale.ROOT).contains("SDK")) {
            // Make sure we have a consistent name whatever the orientation.
            if (InstrumentationRegistry.getContext().getResources().getConfiguration().orientation
                    == Configuration.ORIENTATION_PORTRAIT) {
                model = "Emulator_" + mDevice.getDisplayHeight() + '_' + mDevice.getDisplayWidth();
            } else {
                model = "Emulator_" + mDevice.getDisplayWidth() + '_' + mDevice.getDisplayHeight();
            }
        }
        return model;
    }

    private String imageName(String shotName) {
        int orientation =
                InstrumentationRegistry.getContext().getResources().getConfiguration().orientation;
        String orientationName =
                orientation == Configuration.ORIENTATION_LANDSCAPE ? "landscape" : "portrait";
        return String.format("%s.%s.%s.png", shotName, mModel, orientationName);
    }
}
