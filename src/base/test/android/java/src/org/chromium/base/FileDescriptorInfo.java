// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base;

import android.annotation.SuppressLint;
import android.os.Parcel;
import android.os.ParcelFileDescriptor;
import android.os.Parcelable;

/**
 * Parcelable class that contains file descriptor and a key that identifies it.
 * TODO(jcivelli): should be merged with
 * org.chromium.content.common.FileDescriptorInfo
 */
@SuppressLint("ParcelClassLoader")
public final class FileDescriptorInfo implements Parcelable {
    /** An consumer chosen ID that uniquely identifies a file descriptor. */
    public final int key;

    /** A file descriptor to access the file. */
    public final ParcelFileDescriptor fd;

    public FileDescriptorInfo(int key, ParcelFileDescriptor fd) {
        this.key = key;
        this.fd = fd;
    }

    FileDescriptorInfo(Parcel in) {
        key = in.readInt();
        fd = in.readParcelable(null);
    }

    @Override
    public int describeContents() {
        return CONTENTS_FILE_DESCRIPTOR;
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeInt(key);
        dest.writeParcelable(fd, CONTENTS_FILE_DESCRIPTOR);
    }

    public static final Parcelable.Creator<FileDescriptorInfo> CREATOR =
            new Parcelable.Creator<FileDescriptorInfo>() {
                @Override
                public FileDescriptorInfo createFromParcel(Parcel in) {
                    return new FileDescriptorInfo(in);
                }

                @Override
                public FileDescriptorInfo[] newArray(int size) {
                    return new FileDescriptorInfo[size];
                }
            };
}
