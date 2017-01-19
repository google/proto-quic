// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base;

import android.os.Parcel;
import android.os.Parcelable;

import org.chromium.base.annotations.CalledByNative;
import org.chromium.base.annotations.JNINamespace;

/**
 * Contains the result of a native main method that ran in a child process.
 */
@JNINamespace("base::android")
public final class MainReturnCodeResult implements Parcelable {
    private final int mMainReturnCode;
    private final boolean mTimedOut;

    public MainReturnCodeResult(int mainReturnCode, boolean timedOut) {
        mMainReturnCode = mainReturnCode;
        mTimedOut = timedOut;
    }

    MainReturnCodeResult(Parcel in) {
        mMainReturnCode = in.readInt();
        mTimedOut = (in.readInt() != 0);
    }

    @CalledByNative
    public int getReturnCode() {
        return mMainReturnCode;
    }

    @CalledByNative
    public boolean hasTimedOut() {
        return mTimedOut;
    }

    @Override
    public int describeContents() {
        return 0;
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeInt(mMainReturnCode);
        dest.writeInt(mTimedOut ? 1 : 0);
    }

    public static final Parcelable.Creator<MainReturnCodeResult> CREATOR =
            new Parcelable.Creator<MainReturnCodeResult>() {
                @Override
                public MainReturnCodeResult createFromParcel(Parcel in) {
                    return new MainReturnCodeResult(in);
                }

                @Override
                public MainReturnCodeResult[] newArray(int size) {
                    return new MainReturnCodeResult[size];
                }
            };
}
