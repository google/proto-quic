// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base;

import org.chromium.base.annotations.CalledByNative;

/**
 * A simple single-argument callback to handle the result of a computation.
 *
 * @param <T> The type of the computation's result.
 */
public abstract class Callback<T> {
    /**
     * Invoked with the result of a computation.
     */
    public abstract void onResult(T result);

    @SuppressWarnings("unchecked")
    @CalledByNative
    private void onResultFromNative(Object result) {
        onResult((T) result);
    }

    @SuppressWarnings("unchecked")
    @CalledByNative
    private void onResultFromNative(boolean result) {
        onResult((T) Boolean.valueOf(result));
    }

    @SuppressWarnings("unchecked")
    @CalledByNative
    private void onResultFromNative(int result) {
        onResult((T) Integer.valueOf(result));
    }

    @SuppressWarnings("unchecked")
    @CalledByNative
    private void onResultFromNative(byte[] result) {
        onResult((T) result);
    }
}
