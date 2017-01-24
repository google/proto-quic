// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base;

import android.annotation.TargetApi;
import android.app.Activity;
import android.app.ActivityManager;
import android.app.Notification;
import android.app.PendingIntent;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.res.ColorStateList;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.content.res.Resources.NotFoundException;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.graphics.ColorFilter;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.Build;
import android.os.PowerManager;
import android.os.Process;
import android.os.StatFs;
import android.os.UserManager;
import android.provider.Settings;
import android.view.View;
import android.view.ViewGroup.MarginLayoutParams;
import android.view.Window;
import android.view.WindowManager;
import android.view.inputmethod.InputMethodSubtype;
import android.widget.RemoteViews;
import android.widget.TextView;

import java.io.File;
import java.lang.reflect.Method;

/**
 * Utility class to use new APIs that were added after ICS (API level 14).
 */
@TargetApi(Build.VERSION_CODES.LOLLIPOP)
public class ApiCompatibilityUtils {
    private ApiCompatibilityUtils() {
    }

    /**
     * Compares two long values numerically. The value returned is identical to what would be
     * returned by {@link Long#compare(long, long)} which is available since API level 19.
     */
    public static int compareLong(long lhs, long rhs) {
        return lhs < rhs ? -1 : (lhs == rhs ? 0 : 1);
    }

    /**
     * Compares two boolean values. The value returned is identical to what would be returned by
     * {@link Boolean#compare(boolean, boolean)} which is available since API level 19.
     */
    public static int compareBoolean(boolean lhs, boolean rhs) {
        return lhs == rhs ? 0 : lhs ? 1 : -1;
    }

    /**
     * Returns true if view's layout direction is right-to-left.
     *
     * @param view the View whose layout is being considered
     */
    public static boolean isLayoutRtl(View view) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
            return view.getLayoutDirection() == View.LAYOUT_DIRECTION_RTL;
        } else {
            // All layouts are LTR before JB MR1.
            return false;
        }
    }

    /**
     * @see Configuration#getLayoutDirection()
     */
    public static int getLayoutDirection(Configuration configuration) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
            return configuration.getLayoutDirection();
        } else {
            // All layouts are LTR before JB MR1.
            return View.LAYOUT_DIRECTION_LTR;
        }
    }

    /**
     * @return True if the running version of the Android supports printing.
     */
    public static boolean isPrintingSupported() {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT;
    }

    /**
     * @return True if the running version of the Android supports elevation. Elevation of a view
     * determines the visual appearance of its shadow.
     */
    public static boolean isElevationSupported() {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP;
    }

    /**
     * @see android.view.View#setLayoutDirection(int)
     */
    public static void setLayoutDirection(View view, int layoutDirection) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
            view.setLayoutDirection(layoutDirection);
        } else {
            // Do nothing. RTL layouts aren't supported before JB MR1.
        }
    }

    /**
     * @see android.view.View#setTextAlignment(int)
     */
    public static void setTextAlignment(View view, int textAlignment) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
            view.setTextAlignment(textAlignment);
        } else {
            // Do nothing. RTL text isn't supported before JB MR1.
        }
    }

    /**
     * @see android.view.View#setTextDirection(int)
     */
    public static void setTextDirection(View view, int textDirection) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
            view.setTextDirection(textDirection);
        } else {
            // Do nothing. RTL text isn't supported before JB MR1.
        }
    }

    /**
     * See {@link android.view.View#setLabelFor(int)}.
     */
    public static void setLabelFor(View labelView, int id) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
            labelView.setLabelFor(id);
        } else {
            // Do nothing. #setLabelFor() isn't supported before JB MR1.
        }
    }

    /**
     * @see android.view.ViewGroup.MarginLayoutParams#setMarginEnd(int)
     */
    public static void setMarginEnd(MarginLayoutParams layoutParams, int end) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
            layoutParams.setMarginEnd(end);
        } else {
            layoutParams.rightMargin = end;
        }
    }

    /**
     * @see android.view.ViewGroup.MarginLayoutParams#getMarginEnd()
     */
    public static int getMarginEnd(MarginLayoutParams layoutParams) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
            return layoutParams.getMarginEnd();
        } else {
            return layoutParams.rightMargin;
        }
    }

    /**
     * @see android.view.ViewGroup.MarginLayoutParams#setMarginStart(int)
     */
    public static void setMarginStart(MarginLayoutParams layoutParams, int start) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
            layoutParams.setMarginStart(start);
        } else {
            layoutParams.leftMargin = start;
        }
    }

    /**
     * @see android.view.ViewGroup.MarginLayoutParams#getMarginStart()
     */
    public static int getMarginStart(MarginLayoutParams layoutParams) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
            return layoutParams.getMarginStart();
        } else {
            return layoutParams.leftMargin;
        }
    }

    /**
     * @see android.view.View#setPaddingRelative(int, int, int, int)
     */
    public static void setPaddingRelative(View view, int start, int top, int end, int bottom) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
            view.setPaddingRelative(start, top, end, bottom);
        } else {
            // Before JB MR1, all layouts are left-to-right, so start == left, etc.
            view.setPadding(start, top, end, bottom);
        }
    }

    /**
     * @see android.view.View#getPaddingStart()
     */
    public static int getPaddingStart(View view) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
            return view.getPaddingStart();
        } else {
            // Before JB MR1, all layouts are left-to-right, so start == left.
            return view.getPaddingLeft();
        }
    }

    /**
     * @see android.view.View#getPaddingEnd()
     */
    public static int getPaddingEnd(View view) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
            return view.getPaddingEnd();
        } else {
            // Before JB MR1, all layouts are left-to-right, so end == right.
            return view.getPaddingRight();
        }
    }

    /**
     * @see android.widget.TextView#setCompoundDrawablesRelative(Drawable, Drawable, Drawable,
     *      Drawable)
     */
    public static void setCompoundDrawablesRelative(TextView textView, Drawable start, Drawable top,
            Drawable end, Drawable bottom) {
        if (Build.VERSION.SDK_INT == Build.VERSION_CODES.JELLY_BEAN_MR1) {
            // On JB MR1, due to a platform bug, setCompoundDrawablesRelative() is a no-op if the
            // view has ever been measured. As a workaround, use setCompoundDrawables() directly.
            // See: http://crbug.com/368196 and http://crbug.com/361709
            boolean isRtl = isLayoutRtl(textView);
            textView.setCompoundDrawables(isRtl ? end : start, top, isRtl ? start : end, bottom);
        } else if (Build.VERSION.SDK_INT > Build.VERSION_CODES.JELLY_BEAN_MR1) {
            textView.setCompoundDrawablesRelative(start, top, end, bottom);
        } else {
            textView.setCompoundDrawables(start, top, end, bottom);
        }
    }

    /**
     * @see android.widget.TextView#setCompoundDrawablesRelativeWithIntrinsicBounds(Drawable,
     *      Drawable, Drawable, Drawable)
     */
    public static void setCompoundDrawablesRelativeWithIntrinsicBounds(TextView textView,
            Drawable start, Drawable top, Drawable end, Drawable bottom) {
        if (Build.VERSION.SDK_INT == Build.VERSION_CODES.JELLY_BEAN_MR1) {
            // Work around the platform bug described in setCompoundDrawablesRelative() above.
            boolean isRtl = isLayoutRtl(textView);
            textView.setCompoundDrawablesWithIntrinsicBounds(isRtl ? end : start, top,
                    isRtl ? start : end, bottom);
        } else if (Build.VERSION.SDK_INT > Build.VERSION_CODES.JELLY_BEAN_MR1) {
            textView.setCompoundDrawablesRelativeWithIntrinsicBounds(start, top, end, bottom);
        } else {
            textView.setCompoundDrawablesWithIntrinsicBounds(start, top, end, bottom);
        }
    }

    /**
     * @see android.widget.TextView#setCompoundDrawablesRelativeWithIntrinsicBounds(int, int, int,
     *      int)
     */
    public static void setCompoundDrawablesRelativeWithIntrinsicBounds(TextView textView,
            int start, int top, int end, int bottom) {
        if (Build.VERSION.SDK_INT == Build.VERSION_CODES.JELLY_BEAN_MR1) {
            // Work around the platform bug described in setCompoundDrawablesRelative() above.
            boolean isRtl = isLayoutRtl(textView);
            textView.setCompoundDrawablesWithIntrinsicBounds(isRtl ? end : start, top,
                    isRtl ? start : end, bottom);
        } else if (Build.VERSION.SDK_INT > Build.VERSION_CODES.JELLY_BEAN_MR1) {
            textView.setCompoundDrawablesRelativeWithIntrinsicBounds(start, top, end, bottom);
        } else {
            textView.setCompoundDrawablesWithIntrinsicBounds(start, top, end, bottom);
        }
    }

    // These methods have a new name, and the old name is deprecated.

    /**
     * @see android.app.PendingIntent#getCreatorPackage()
     */
    @SuppressWarnings("deprecation")
    public static String getCreatorPackage(PendingIntent intent) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
            return intent.getCreatorPackage();
        } else {
            return intent.getTargetPackage();
        }
    }

    /**
     * @see android.provider.Settings.Global#DEVICE_PROVISIONED
     */
    @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR1)
    public static boolean isDeviceProvisioned(Context context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.JELLY_BEAN_MR1) return true;
        if (context == null) return true;
        if (context.getContentResolver() == null) return true;
        return Settings.Global.getInt(
                context.getContentResolver(), Settings.Global.DEVICE_PROVISIONED, 0) != 0;
    }

    /**
     * @see android.app.Activity#finishAndRemoveTask()
     */
    public static void finishAndRemoveTask(Activity activity) {
        if (Build.VERSION.SDK_INT > Build.VERSION_CODES.LOLLIPOP) {
            activity.finishAndRemoveTask();
        } else if (Build.VERSION.SDK_INT == Build.VERSION_CODES.LOLLIPOP) {
            // crbug.com/395772 : Fallback for Activity.finishAndRemoveTask() failing.
            new FinishAndRemoveTaskWithRetry(activity).run();
        } else {
            activity.finish();
        }
    }

    /**
     * Set elevation if supported.
     */
    @TargetApi(Build.VERSION_CODES.LOLLIPOP)
    public static boolean setElevation(View view, float elevationValue) {
        if (!isElevationSupported()) return false;

        view.setElevation(elevationValue);
        return true;
    }

    private static class FinishAndRemoveTaskWithRetry implements Runnable {
        private static final long RETRY_DELAY_MS = 500;
        private static final long MAX_TRY_COUNT = 3;
        private final Activity mActivity;
        private int mTryCount;

        FinishAndRemoveTaskWithRetry(Activity activity) {
            mActivity = activity;
        }

        @Override
        public void run() {
            mActivity.finishAndRemoveTask();
            mTryCount++;
            if (!mActivity.isFinishing()) {
                if (mTryCount < MAX_TRY_COUNT) {
                    ThreadUtils.postOnUiThreadDelayed(this, RETRY_DELAY_MS);
                } else {
                    mActivity.finish();
                }
            }
        }
    }

    /**
     * @return Whether the screen of the device is interactive.
     */
    @SuppressWarnings("deprecation")
    public static boolean isInteractive(Context context) {
        PowerManager manager = (PowerManager) context.getSystemService(Context.POWER_SERVICE);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT_WATCH) {
            return manager.isInteractive();
        } else {
            return manager.isScreenOn();
        }
    }

    @SuppressWarnings("deprecation")
    public static int getActivityNewDocumentFlag() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            return Intent.FLAG_ACTIVITY_NEW_DOCUMENT;
        } else {
            return Intent.FLAG_ACTIVITY_CLEAR_WHEN_TASK_RESET;
        }
    }

    /**
     * @see android.provider.Settings.Secure#SKIP_FIRST_USE_HINTS
     */
    public static boolean shouldSkipFirstUseHints(ContentResolver contentResolver) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            return Settings.Secure.getInt(
                    contentResolver, Settings.Secure.SKIP_FIRST_USE_HINTS, 0) != 0;
        } else {
            return false;
        }
    }

    /**
     * @param activity Activity that should get the task description update.
     * @param title Title of the activity.
     * @param icon Icon of the activity.
     * @param color Color of the activity. It must be a fully opaque color.
     */
    public static void setTaskDescription(Activity activity, String title, Bitmap icon, int color) {
        // TaskDescription requires an opaque color.
        assert Color.alpha(color) == 255;

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            ActivityManager.TaskDescription description =
                    new ActivityManager.TaskDescription(title, icon, color);
            activity.setTaskDescription(description);
        }
    }

    /**
     * @see android.view.Window#setStatusBarColor(int color).
     */
    public static void setStatusBarColor(Window window, int statusBarColor) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            // If both system bars are black, we can remove these from our layout,
            // removing or shrinking the SurfaceFlinger overlay required for our views.
            if (statusBarColor == Color.BLACK && window.getNavigationBarColor() == Color.BLACK) {
                window.clearFlags(WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS);
            } else {
                window.addFlags(WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS);
            }
            window.setStatusBarColor(statusBarColor);
        }
    }

    /**
     * @see android.content.res.Resources#getDrawable(int id).
     */
    @SuppressWarnings("deprecation")
    public static Drawable getDrawable(Resources res, int id) throws NotFoundException {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            return res.getDrawable(id, null);
        } else {
            return res.getDrawable(id);
        }
    }

    /**
     * @see android.content.res.Resources#getDrawableForDensity(int id, int density).
     */
    @SuppressWarnings("deprecation")
    public static Drawable getDrawableForDensity(Resources res, int id, int density) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            return res.getDrawableForDensity(id, density, null);
        } else {
            return res.getDrawableForDensity(id, density);
        }
    }

    /**
     * @see android.app.Activity#finishAfterTransition().
     */
    public static void finishAfterTransition(Activity activity) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            activity.finishAfterTransition();
        } else {
            activity.finish();
        }
    }

    /**
     * @see android.content.pm.PackageManager#getUserBadgedIcon(Drawable, android.os.UserHandle).
     */
    public static Drawable getUserBadgedIcon(Context context, int id) {
        Drawable drawable = getDrawable(context.getResources(), id);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            PackageManager packageManager = context.getPackageManager();
            drawable = packageManager.getUserBadgedIcon(drawable, Process.myUserHandle());
        }
        return drawable;
    }

    /**
     * @see android.content.pm.PackageManager#getUserBadgedDrawableForDensity(Drawable drawable,
     * UserHandle user, Rect badgeLocation, int badgeDensity).
     */
    public static Drawable getUserBadgedDrawableForDensity(
            Context context, Drawable drawable, Rect badgeLocation, int density) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            PackageManager packageManager = context.getPackageManager();
            return packageManager.getUserBadgedDrawableForDensity(
                    drawable, Process.myUserHandle(), badgeLocation, density);
        }
        return drawable;
    }

    /**
     * @see android.content.res.Resources#getColor(int id).
     */
    @SuppressWarnings("deprecation")
    public static int getColor(Resources res, int id) throws NotFoundException {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            return res.getColor(id, null);
        } else {
            return res.getColor(id);
        }
    }

    /**
     * @see android.graphics.drawable.Drawable#getColorFilter().
     */
    @SuppressWarnings("NewApi")
    public static ColorFilter getColorFilter(Drawable drawable) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            return drawable.getColorFilter();
        } else {
            return null;
        }
    }

    /**
     * @see android.content.res.Resources#getColorStateList(int id).
     */
    @SuppressWarnings("deprecation")
    public static ColorStateList getColorStateList(Resources res, int id) throws NotFoundException {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            return res.getColorStateList(id, null);
        } else {
            return res.getColorStateList(id);
        }
    }

    /**
     * @see android.widget.TextView#setTextAppearance(int id).
     */
    @SuppressWarnings("deprecation")
    public static void setTextAppearance(TextView view, int id) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            view.setTextAppearance(id);
        } else {
            view.setTextAppearance(view.getContext(), id);
        }
    }

    /**
     * See {@link android.os.StatFs#getAvailableBlocksLong}.
     */
    @SuppressWarnings("deprecation")
    public static long getAvailableBlocks(StatFs statFs) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
            return statFs.getAvailableBlocksLong();
        } else {
            return statFs.getAvailableBlocks();
        }
    }

    /**
     * See {@link android.os.StatFs#getBlockCount}.
     */
    @SuppressWarnings("deprecation")
    public static long getBlockCount(StatFs statFs) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
            return statFs.getBlockCountLong();
        } else {
            return statFs.getBlockCount();
        }
    }

    /**
     * See {@link android.os.StatFs#getBlockSize}.
     */
    @SuppressWarnings("deprecation")
    public static long getBlockSize(StatFs statFs) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
            return statFs.getBlockSizeLong();
        } else {
            return statFs.getBlockSize();
        }
    }

    /**
     * @param context The Android context, used to retrieve the UserManager system service.
     * @return Whether the device is running in demo mode.
     */
    public static boolean isDemoUser(Context context) {
        // UserManager#isDemoUser() is only available in Android versions greater than N.
        if (!BuildInfo.isGreaterThanN()) return false;

        try {
            UserManager userManager = (UserManager) context.getSystemService(Context.USER_SERVICE);
            Method isDemoUserMethod = UserManager.class.getMethod("isDemoUser");
            boolean isDemoUser = (boolean) isDemoUserMethod.invoke(userManager);
            return isDemoUser;
        } catch (RuntimeException e) {
            // Ignore to avoid crashing on startup.
        } catch (Exception e) {
            // Ignore.
        }

        return false;
    }

    /**
     * @see Context#checkPermission(String, int, int)
     */
    public static int checkPermission(Context context, String permission, int pid, int uid) {
        try {
            return context.checkPermission(permission, pid, uid);
        } catch (RuntimeException e) {
            // Some older versions of Android throw odd errors when checking for permissions, so
            // just swallow the exception and treat it as the permission is denied.
            // crbug.com/639099
            return PackageManager.PERMISSION_DENIED;
        }
    }

    /**
     * @see android.app.Notification.Builder#setContent(RemoteViews)
     */
    @SuppressWarnings("deprecation")
    public static void setContentViewForNotificationBuilder(
            Notification.Builder builder, RemoteViews views) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            builder.setCustomContentView(views);
        } else {
            builder.setContent(views);
        }
    }

    /**
     * @see android.app.Notification#bigContentView
     */
    @SuppressWarnings("deprecation")
    public static Notification notificationWithBigContentView(
            Notification.Builder builder, RemoteViews view) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            return builder.setCustomBigContentView(view).build();
        } else {
            Notification notification = builder.build();
            notification.bigContentView = view;
            return notification;
        }
    }

    /**
     * @see android.view.inputmethod.InputMethodSubType#getLocate()
     */
    @SuppressWarnings("deprecation")
    public static String getLocale(InputMethodSubtype inputMethodSubType) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            return inputMethodSubType.getLanguageTag();
        } else {
            return inputMethodSubType.getLocale();
        }
    }

    /**
     * Get a URI for |file| which has the image capture. This function assumes that path of |file|
     * is based on the result of UiUtils.getDirectoryForImageCapture().
     *
     * @param context The application context.
     * @param file image capture file.
     * @return URI for |file|.
     */
    public static Uri getUriForImageCaptureFile(Context context, File file) {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2
                ? ContentUriUtils.getContentUriFromFile(context, file)
                : Uri.fromFile(file);
    }

    /**
     * @see android.view.Window#FEATURE_INDETERMINATE_PROGRESS
     */
    public static void setWindowIndeterminateProgress(Window window) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
            @SuppressWarnings("deprecation")
            int featureNumber = Window.FEATURE_INDETERMINATE_PROGRESS;

            @SuppressWarnings("deprecation")
            int featureValue = Window.PROGRESS_VISIBILITY_OFF;

            window.setFeatureInt(featureNumber, featureValue);
        }
    }
}
