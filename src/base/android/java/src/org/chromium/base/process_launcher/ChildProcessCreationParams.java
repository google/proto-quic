// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base.process_launcher;

import android.content.Intent;
import android.util.SparseArray;

import org.chromium.base.library_loader.LibraryProcessType;

import javax.annotation.concurrent.GuardedBy;

/**
 * Allows specifying the package name for looking up child services
 * configuration and classes into (if it differs from the application package
 * name, like in the case of Android WebView). Also allows specifying additional
 * child service binging flags.
 */
public class ChildProcessCreationParams {
    private static final String EXTRA_LIBRARY_PROCESS_TYPE =
            "org.chromium.content.common.child_service_params.library_process_type";

    /** ID used for the default params. */
    public static final int DEFAULT_ID = 0;

    private static final Object sLock = new Object();
    @GuardedBy("sLock")
    private static final SparseArray<ChildProcessCreationParams> sParamMap = new SparseArray<>();
    @GuardedBy("sLock")
    private static int sNextId = 1; // 0 is reserved for DEFAULT_ID.

    /** Registers default params. This should be called once on start up. */
    public static void registerDefault(ChildProcessCreationParams params) {
        synchronized (sLock) {
            // TODO(boliu): Assert not overwriting existing entry once WebApk is fixed.
            sParamMap.append(DEFAULT_ID, params);
        }
    }

    public static ChildProcessCreationParams getDefault() {
        return get(DEFAULT_ID);
    }

    /** Registers new params. Returns the allocated ID corresponding this params. */
    public static int register(ChildProcessCreationParams params) {
        assert params != null;
        int id = -1;
        synchronized (sLock) {
            id = sNextId++;
            sParamMap.append(id, params);
        }
        assert id > 0;
        return id;
    }

    /** Releases param corresponding to this ID. Any future use of this ID will crash. */
    public static void unregister(int id) {
        assert id > DEFAULT_ID; // Not allowed to unregister default.
        synchronized (sLock) {
            sParamMap.delete(id);
        }
    }

    public static ChildProcessCreationParams get(int id) {
        assert id >= 0;
        synchronized (sLock) {
            return sParamMap.get(id);
        }
    }

    // Members should all be immutable to avoid worrying about thread safety.
    private final String mPackageName;
    private final boolean mIsExternalService;
    private final int mLibraryProcessType;
    private final boolean mBindToCallerCheck;

    public ChildProcessCreationParams(String packageName, boolean isExternalService,
            int libraryProcessType, boolean bindToCallerCheck) {
        mPackageName = packageName;
        mIsExternalService = isExternalService;
        mLibraryProcessType = libraryProcessType;
        mBindToCallerCheck = bindToCallerCheck;
    }

    public String getPackageName() {
        return mPackageName;
    }

    public boolean getIsExternalService() {
        return mIsExternalService;
    }

    public int getLibraryProcessType() {
        return mLibraryProcessType;
    }

    public boolean getBindToCallerCheck() {
        return mBindToCallerCheck;
    }

    public void addIntentExtras(Intent intent) {
        intent.putExtra(EXTRA_LIBRARY_PROCESS_TYPE, mLibraryProcessType);
    }

    public static int getLibraryProcessType(Intent intent) {
        return intent.getIntExtra(EXTRA_LIBRARY_PROCESS_TYPE, LibraryProcessType.PROCESS_CHILD);
    }
}
