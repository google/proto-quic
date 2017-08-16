// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.build;

import android.content.res.Resources;

/**
 * All Java targets that require android have dependence on this class. Add methods that do not
 * require Android to {@link BuildHooks}.
 *
 * This class provides hooks needed when bytecode rewriting. Static convenience methods are used to
 * minimize the amount of code required to be manually generated when bytecode rewriting.
 *
 * This class contains default implementations for all methods and is used when no other
 * implementation is supplied to an android_apk target (via build_hooks_android_impl_deps).
 */
public abstract class BuildHooksAndroid {
    private static BuildHooksAndroidImpl sInstance = new BuildHooksAndroidImpl();

    /**
     * Hook to provide custom resources.
     * @param resources fallback resources to use if custom resources aren't available.
     * @return custom resources.
     */
    public static Resources getResources(Resources resources) {
        return sInstance.getResourcesImpl(resources);
    }

    protected Resources getResourcesImpl(Resources resources) {
        return resources;
    }
}