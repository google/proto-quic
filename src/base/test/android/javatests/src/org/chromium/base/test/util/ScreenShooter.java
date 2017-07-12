// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base.test.util;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import android.app.Instrumentation;
import android.content.res.Configuration;
import android.graphics.Point;
import android.os.Build;
import android.support.test.InstrumentationRegistry;
import android.support.test.uiautomator.UiDevice;

import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

import java.io.File;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.Locale;

/**
 * Rule for taking screen shots within tests. Screenshots are saved as
 * UiCapture/<test class directory>/<test directory>/<shot name>.png.
 *
 * <test class directory> and <test directory> can both the set by the @ScreenShooter.Directory
 * annotation. <test class directory> defaults to nothing (i.e. no directory created at this
 * level), and <test directory> defaults to the name of the individual test.
 *
 * A simple example:
 *
 * <pre>
 * {
 * @RunWith(ChromeJUnit4ClassRunner.class)
 * @CommandLineFlags.Add({ChromeSwitches.DISABLE_FIRST_RUN_EXPERIENCE})
 * @Restriction(RESTRICTION_TYPE_PHONE) // Tab switcher button only exists on phones.
 * @ScreenShooter.Directory("Example")
 * public class ExampleUiCaptureTest {
 *     @Rule
 *     public ChromeActivityTestRule<ChromeTabbedActivity> mActivityTestRule =
 *             new ChromeActivityTestRule<>(ChromeTabbedActivity.class);
 *
 *     @Rule
 *     public ScreenShooter mScreenShooter = new ScreenShooter();
 *
 *     @Before
 *     public void setUp() throws InterruptedException {
 *         mActivityTestRule.startMainActivityFromLauncher();
 *     }
 *
 *     // Capture the New Tab Page and the tab switcher.
 *     @Test
 *     @SmallTest
 *     @Feature({"UiCatalogue"})
 *     @ScreenShooter.Directory("TabSwitcher")
 *     public void testCaptureTabSwitcher() throws IOException, InterruptedException {
 *         mScreenShooter.shoot("NTP");
 *         Espresso.onView(ViewMatchers.withId(R.id.tab_switcher_button)).
 *                      perform(ViewActions.click());
 *         mScreenShooter.shoot("Tab switcher");
 *     }
 * }
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

    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.TYPE, ElementType.METHOD})
    public @interface Directory {
        String value();
    }

    public ScreenShooter() {
        mInstrumentation = InstrumentationRegistry.getInstrumentation();
        mDevice = UiDevice.getInstance(mInstrumentation);
        mBaseDir = InstrumentationRegistry.getArguments().getString(SCREENSHOT_DIR);
        mModel = getModelName();
    }

    @Override
    protected void starting(Description d) {
        mDir = new File(mBaseDir);
        Class<?> testClass = d.getTestClass();
        Directory classDirectoryAnnotation = testClass.getAnnotation(Directory.class);
        String classDirName = classDirectoryAnnotation == null ? ""
                : classDirectoryAnnotation.value();
        if (!classDirName.isEmpty()) mDir = new File(mBaseDir, classDirName);
        Directory methodDirectoryAnnotation = d.getAnnotation(Directory.class);
        String testMethodDir = methodDirectoryAnnotation == null ? d.getMethodName()
                : methodDirectoryAnnotation.value();
        if (!testMethodDir.isEmpty()) mDir = new File(mDir, testMethodDir);
        if (!mDir.exists()) assertTrue("Create screenshot directory", mDir.mkdirs());
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
            Point displaySize = mDevice.getDisplaySizeDp();
            // Make sure we have a consistent name whatever the orientation.
            if (InstrumentationRegistry.getContext().getResources()
                    .getConfiguration().orientation == Configuration.ORIENTATION_PORTRAIT) {
                model = "Emulator_" + displaySize.y + '_' + displaySize.x;
            } else {
                model = "Emulator_" + displaySize.x + '_' + displaySize.y;
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
