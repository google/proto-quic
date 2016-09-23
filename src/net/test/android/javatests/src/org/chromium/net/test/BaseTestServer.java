// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.net.test;

import org.chromium.base.Log;

import java.util.concurrent.atomic.AtomicBoolean;

/** A base class for simple test servers. */
public abstract class BaseTestServer implements Runnable {
    private static final String TAG = "net_test";

    private AtomicBoolean mKeepRunning;
    private final Object mLock;
    private boolean mRunning;

    /** Creates a test server. */
    public BaseTestServer() {
        mKeepRunning = new AtomicBoolean(true);
        mLock = new Object();
    }

    /** Accepts incoming connections until stopped via stop(). */
    public void run() {
        serverHasStarted();

        try {
            while (mKeepRunning.get()) {
                accept();
            }
        } finally {
            serverHasStopped();
        }
    }

    /** Waits for the server to start. */
    public void waitForServerToStart() {
        synchronized (mLock) {
            while (!mRunning) {
                try {
                    mLock.wait();
                } catch (InterruptedException e) {
                    Log.e(TAG, "Interrupted while waiting for server to stop.", e);
                }
            }
        }
    }

    private void serverHasStarted() {
        synchronized (mLock) {
            mRunning = true;
            mLock.notifyAll();
        }
    }

    /** Waits for and handles an incoming request. */
    protected abstract void accept();

    /** Returns the port on which this server is listening for connections. */
    public abstract int getServerPort();

    /** Stops the server. */
    public void stop() {
        mKeepRunning.set(false);
    }

    private void serverHasStopped() {
        synchronized (mLock) {
            mRunning = false;
            mLock.notifyAll();
        }
    }
}
