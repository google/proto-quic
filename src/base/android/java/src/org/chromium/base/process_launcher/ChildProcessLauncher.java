// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base.process_launcher;

import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;

import org.chromium.base.ContextUtils;
import org.chromium.base.Log;
import org.chromium.base.TraceEvent;
import org.chromium.base.annotations.SuppressFBWarnings;

import java.io.IOException;

/**
 * This class is used to start a child process by connecting to a ChildProcessService.
 */
public class ChildProcessLauncher {
    private static final String TAG = "ChildProcLauncher";

    /** Delegate that client should use to customize the process launching. */
    public interface Delegate {
        /**
         * Called before a connection is allocated.
         * Note that this is only called if the ChildProcessLauncher is created with
         * {@link #createWithConnectionAllocator}.
         * @param serviceBundle the bundle passed in the service intent. Clients can add their own
         * extras to the bundle.
         */
        void onBeforeConnectionAllocated(Bundle serviceBundle);

        /**
         * Called before setup is called on the connection.
         * @param connectionBundle the bundle passed to the {@link ChildProcessService} in the
         * setup call. Clients can add their own extras to the bundle.
         */
        void onBeforeConnectionSetup(Bundle connectionBundle);

        /**
         * Called when the connection was successfully established, meaning the setup call on the
         * service was successful.
         * @param connection the connection over which the setup call was made.
         */
        void onConnectionEstablished(ChildProcessConnection connection);

        /**
         * Called when a connection has been disconnected. Only invoked if onConnectionEstablished
         * was called, meaning the connection was already established.
         * @param connection the connection that got disconnected.
         */
        void onConnectionLost(ChildProcessConnection connection);
    }

    /**
     * Interface used by clients that already have a bound connection ready when instanciating the
     * ChildProcessLauncher.
     */
    public interface BoundConnectionProvider {
        ChildProcessConnection getConnection(
                ChildProcessConnection.ServiceCallback serviceCallback);
    }

    // Represents an invalid process handle; same as base/process/process.h kNullProcessHandle.
    private static final int NULL_PROCESS_HANDLE = 0;

    // The handle for the thread we were created on and on which all methods should be called.
    private final Handler mLauncherHandler;

    private final Delegate mDelegate;

    private final String[] mCommandLine;
    private final FileDescriptorInfo[] mFilesToBeMapped;

    // The allocator used to create the connection.
    private final BoundConnectionProvider mConnectionProvider;

    // The allocator used to create the connection.
    private final ChildConnectionAllocator mConnectionAllocator;

    // The IBinder provided to the created service.
    private final IBinder mIBinderCallback;

    // The actual service connection. Set once we have connected to the service.
    private ChildProcessConnection mConnection;

    /**
     * Creates a ChildProcessLauncher using the already bound connection provided.
     * Note that onBeforeConnectionAllocated and onConnectionBound will not be invoked on the
     * delegate since the connection is already available.
     */
    public static ChildProcessLauncher createWithBoundConnectionProvider(Handler launcherHandler,
            Delegate delegate, String[] commandLine, FileDescriptorInfo[] filesToBeMapped,
            BoundConnectionProvider connectionProvider, IBinder binderCallback) {
        return new ChildProcessLauncher(launcherHandler, delegate, commandLine, filesToBeMapped,
                connectionProvider, null /* connectionAllocator */, binderCallback);
    }

    /**
     * Creates a ChildProcessLauncher that will create a connection using the specified
     * ChildConnectionAllocator.
     */
    public static ChildProcessLauncher createWithConnectionAllocator(Handler launcherHandler,
            Delegate delegate, String[] commandLine, FileDescriptorInfo[] filesToBeMapped,
            ChildConnectionAllocator connectionAllocator, IBinder binderCallback) {
        return new ChildProcessLauncher(launcherHandler, delegate, commandLine, filesToBeMapped,
                null /* connection */, connectionAllocator, binderCallback);
    }

    @SuppressFBWarnings("EI_EXPOSE_REP2")
    private ChildProcessLauncher(Handler launcherHandler, Delegate delegate, String[] commandLine,
            FileDescriptorInfo[] filesToBeMapped, BoundConnectionProvider connectionProvider,
            ChildConnectionAllocator connectionAllocator, IBinder binderCallback) {
        // Either a bound connection provider or a connection allocator should be provided.
        assert (connectionProvider == null) != (connectionAllocator == null);
        mLauncherHandler = launcherHandler;
        isRunningOnLauncherThread();
        mCommandLine = commandLine;
        mConnectionProvider = connectionProvider;
        mConnectionAllocator = connectionAllocator;
        mDelegate = delegate;
        mFilesToBeMapped = filesToBeMapped;
        mIBinderCallback = binderCallback;
    }

    /**
     * Starts the child process and calls setup on it if {@param setupConnection} is true.
     * @param setupConnection whether the setup should be performed on the connection once
     * established
     * @param queueIfNoFreeConnection whether to queue that request if no service connection is
     * available. If the launcher was created with a connection provider, this parameter has no
     * effect.
     * @return true if the connection was started or was queued.
     */
    public boolean start(final boolean setupConnection, final boolean queueIfNoFreeConnection) {
        assert isRunningOnLauncherThread();
        try {
            TraceEvent.begin("ChildProcessLauncher.start");
            ChildProcessConnection.ServiceCallback serviceCallback =
                    new ChildProcessConnection.ServiceCallback() {
                        @Override
                        public void onChildStarted() {}

                        @Override
                        public void onChildStartFailed() {
                            assert isRunningOnLauncherThread();
                            Log.e(TAG, "ChildProcessConnection.start failed, trying again");
                            mLauncherHandler.post(new Runnable() {
                                @Override
                                public void run() {
                                    // The child process may already be bound to another client
                                    // (this can happen if multi-process WebView is used in more
                                    // than one process), so try starting the process again.
                                    // This connection that failed to start has not been freed,
                                    // so a new bound connection will be allocated.
                                    mConnection = null;
                                    start(setupConnection, queueIfNoFreeConnection);
                                }
                            });
                        }

                        @Override
                        public void onChildProcessDied(ChildProcessConnection connection) {
                            assert isRunningOnLauncherThread();
                            assert mConnection == connection;
                            ChildProcessLauncher.this.onChildProcessDied();
                        }
                    };
            if (mConnectionProvider != null) {
                mConnection = mConnectionProvider.getConnection(serviceCallback);
                assert mConnection != null;
                setupConnection();
            } else {
                assert mConnectionAllocator != null;
                if (!allocateAndSetupConnection(
                            serviceCallback, setupConnection, queueIfNoFreeConnection)
                        && !queueIfNoFreeConnection) {
                    return false;
                }
            }
            return true;
        } finally {
            TraceEvent.end("ChildProcessLauncher.start");
        }
    }

    public ChildProcessConnection getConnection() {
        return mConnection;
    }

    public ChildConnectionAllocator getConnectionAllocator() {
        return mConnectionAllocator;
    }

    private boolean allocateAndSetupConnection(
            final ChildProcessConnection.ServiceCallback serviceCallback,
            final boolean setupConnection, final boolean queueIfNoFreeConnection) {
        assert mConnection == null;
        Bundle serviceBundle = new Bundle();
        mDelegate.onBeforeConnectionAllocated(serviceBundle);

        mConnection = mConnectionAllocator.allocate(
                ContextUtils.getApplicationContext(), serviceBundle, serviceCallback);
        if (mConnection == null) {
            if (!queueIfNoFreeConnection) {
                Log.d(TAG, "Failed to allocate a child connection (no queuing).");
                return false;
            }
            // No connection is available at this time. Add a listener so when one becomes
            // available we can create the service.
            mConnectionAllocator.addListener(new ChildConnectionAllocator.Listener() {
                @Override
                public void onConnectionFreed(
                        ChildConnectionAllocator allocator, ChildProcessConnection connection) {
                    assert allocator == mConnectionAllocator;
                    if (!allocator.isFreeConnectionAvailable()) return;
                    allocator.removeListener(this);
                    allocateAndSetupConnection(
                            serviceCallback, setupConnection, queueIfNoFreeConnection);
                }
            });
            return false;
        }
        assert mConnection != null;

        if (setupConnection) {
            setupConnection();
        }
        return true;
    }

    private void setupConnection() {
        ChildProcessConnection.ConnectionCallback connectionCallback =
                new ChildProcessConnection.ConnectionCallback() {
                    @Override
                    public void onConnected(ChildProcessConnection connection) {
                        assert mConnection == connection;
                        onServiceConnected();
                    }
                };
        Bundle connectionBundle = createConnectionBundle();
        mDelegate.onBeforeConnectionSetup(connectionBundle);
        mConnection.setupConnection(connectionBundle, getIBinderCallback(), connectionCallback);
    }

    private void onServiceConnected() {
        assert isRunningOnLauncherThread();

        Log.d(TAG, "on connect callback, pid=%d", mConnection.getPid());

        mDelegate.onConnectionEstablished(mConnection);

        // Proactively close the FDs rather than waiting for the GC to do it.
        try {
            for (FileDescriptorInfo fileInfo : mFilesToBeMapped) {
                fileInfo.fd.close();
            }
        } catch (IOException ioe) {
            Log.w(TAG, "Failed to close FD.", ioe);
        }
    }

    public int getPid() {
        assert isRunningOnLauncherThread();
        return mConnection == null ? NULL_PROCESS_HANDLE : mConnection.getPid();
    }

    public IBinder getIBinderCallback() {
        return mIBinderCallback;
    }

    private boolean isRunningOnLauncherThread() {
        return mLauncherHandler.getLooper() == Looper.myLooper();
    }

    private Bundle createConnectionBundle() {
        Bundle bundle = new Bundle();
        bundle.putStringArray(ChildProcessConstants.EXTRA_COMMAND_LINE, mCommandLine);
        bundle.putParcelableArray(ChildProcessConstants.EXTRA_FILES, mFilesToBeMapped);
        return bundle;
    }

    private void onChildProcessDied() {
        assert isRunningOnLauncherThread();
        if (getPid() != 0) {
            mDelegate.onConnectionLost(mConnection);
        }
    }

    public void stop() {
        assert isRunningOnLauncherThread();
        Log.d(TAG, "stopping child connection: pid=%d", mConnection.getPid());
        mConnection.stop();
    }
}
