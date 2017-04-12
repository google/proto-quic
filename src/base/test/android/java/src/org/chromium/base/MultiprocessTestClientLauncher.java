// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;
import android.os.RemoteException;

import org.chromium.base.annotations.CalledByNative;
import org.chromium.base.annotations.JNINamespace;
import org.chromium.base.process_launcher.FileDescriptorInfo;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.CountDownLatch;

import javax.annotation.concurrent.GuardedBy;

/**
 * Helper class for launching test client processes for multiprocess unit tests.
 */
@JNINamespace("base::android")
public final class MultiprocessTestClientLauncher {
    private static final String TAG = "cr_MProcTCLauncher";

    private static ConnectionAllocator sConnectionAllocator = new ConnectionAllocator();

    // Not supposed to be instantiated.
    private MultiprocessTestClientLauncher() {}

    private static class ConnectionAllocator {
        // Services are identified by a slot number, which is used in the service name to
        // differentiate them (MultiprocessTestClientService0, MultiprocessTestClientService1, ...).
        // They are stored in a FIFO queue in order to minimize the risk of the framework reusing a
        // service without restarting its associated process (which can cause all kind of problems
        // with static native variables already being initialized).
        private static final int MAX_SUBPROCESS_COUNT = 5;

        private final Object mLock = new Object();

        @GuardedBy("mLock")
        private final Queue<Integer> mFreeServiceSlot = new LinkedList<>();
        @GuardedBy("mLock")
        private final List<ClientServiceConnection> mConnections = new ArrayList<>();

        public ConnectionAllocator() {
            synchronized (mLock) {
                for (int i = 0; i < MAX_SUBPROCESS_COUNT; i++) {
                    mFreeServiceSlot.add(i);
                }
            }
        }

        public ClientServiceConnection allocateConnection(
                String[] commandLine, FileDescriptorInfo[] filesToMap) {
            synchronized (mLock) {
                while (mFreeServiceSlot.isEmpty()) {
                    try {
                        mLock.wait();
                    } catch (InterruptedException ie) {
                        Log.e(TAG, "Interrupted while waiting for a free connection.");
                    }
                }

                int slot = mFreeServiceSlot.remove();
                ClientServiceConnection connection =
                        new ClientServiceConnection(slot, commandLine, filesToMap);
                mConnections.add(connection);
                return connection;
            }
        }

        public void freeConnection(ClientServiceConnection connection) {
            synchronized (mLock) {
                mFreeServiceSlot.add(connection.getSlot());
                mConnections.remove(connection);
            }
        }

        public ClientServiceConnection getConnectionByPid(int pid) {
            synchronized (mLock) {
                // List of connections is short, iterating is OK.
                for (ClientServiceConnection connection : mConnections) {
                    if (connection.getPid() == pid) {
                        return connection;
                    }
                }
            }
            return null;
        }
    }

    private static class ClientServiceConnection implements ServiceConnection {
        private final Bundle mSetupBundle;
        private final Object mConnectedLock = new Object();
        private final CountDownLatch mPidReceived = new CountDownLatch(1);
        private final int mSlot;
        private ITestClient mService = null;
        @GuardedBy("mConnectedLock")
        private boolean mConnected;
        private int mPid;
        private ITestController mTestController;
        private final ITestCallback.Stub mCallback = new ITestCallback.Stub() {
            public void childConnected(ITestController controller) {
                mTestController = controller;
                // This method can be called before onServiceConnected below has set the PID.
                // Wait for mPid to be set before notifying.
                try {
                    mPidReceived.await();
                } catch (InterruptedException ie) {
                    Log.e(TAG, "Interrupted while waiting for connection PID.");
                    return;
                }
                // Now we are fully initialized, notify clients.
                synchronized (mConnectedLock) {
                    mConnected = true;
                    mConnectedLock.notifyAll();
                }
            }
        };

        ClientServiceConnection(int slot, String[] commandLine, FileDescriptorInfo[] filesToMap) {
            mSlot = slot;
            mSetupBundle = new Bundle();
            mSetupBundle.putStringArray(ChildProcessConstants.EXTRA_COMMAND_LINE, commandLine);
            mSetupBundle.putParcelableArray(ChildProcessConstants.EXTRA_FILES, filesToMap);
        }

        public void waitForConnection() {
            synchronized (mConnectedLock) {
                while (!mConnected) {
                    try {
                        mConnectedLock.wait();
                    } catch (InterruptedException ie) {
                        Log.e(TAG, "Interrupted while waiting for connection.");
                    }
                }
            }
        }

        @Override
        public void onServiceConnected(ComponentName className, IBinder service) {
            try {
                mService = ITestClient.Stub.asInterface(service);
                if (!mService.bindToCaller()) {
                    Log.e(TAG, "Failed to bind to child service");
                    return;
                }
                mPid = mService.setupConnection(mSetupBundle, mCallback);
                mPidReceived.countDown();
            } catch (RemoteException e) {
                Log.e(TAG, "Connect failed");
            }
        }

        @Override
        public void onServiceDisconnected(ComponentName className) {
            if (mPid == 0) {
                Log.e(TAG, "Early ClientServiceConnection disconnection.");
                return;
            }
            sConnectionAllocator.freeConnection(this);
        }

        public ITestController getTestController() {
            return mTestController;
        }

        public String getServiceClassName() {
            // In order to use different processes, we have to declare multiple services in the
            // AndroidManifest.xml file, each service associated with its own process. The various
            // services are functionnaly identical but need to each have their own class.
            // We differentiate them by their class name having a trailing number.
            return MultiprocessTestClientService.class.getName() + mSlot;
        }

        public boolean isConnected() {
            synchronized (mConnectedLock) {
                return mConnected;
            }
        }

        public int getSlot() {
            return mSlot;
        }

        public int getPid() {
            return mPid;
        }
    }

    /**
     * Spawns and connects to a child process.
     * May not be called from the main thread.
     *
     * @param commandLine the child process command line argv.
     * @return the PID of the started process or 0 if the process could not be started.
     */
    @CalledByNative
    private static int launchClient(
            final String[] commandLine, final FileDescriptorInfo[] filesToMap) {
        if (ThreadUtils.runningOnUiThread()) {
            // This can't be called on the main thread as the native side will block until
            // onServiceConnected above is called, which cannot happen if the main thread is
            // blocked.
            throw new RuntimeException("launchClient cannot be called on the main thread");
        }

        ClientServiceConnection connection =
                sConnectionAllocator.allocateConnection(commandLine, filesToMap);
        Intent intent = new Intent();
        String className = connection.getServiceClassName();
        String packageName = ContextUtils.getApplicationContext().getPackageName();
        intent.setComponent(new ComponentName(packageName, className));
        if (!ContextUtils.getApplicationContext().bindService(
                    intent, connection, Context.BIND_AUTO_CREATE | Context.BIND_IMPORTANT)) {
            Log.e(TAG, "Failed to bind service: " + packageName + "." + className);
            sConnectionAllocator.freeConnection(connection);
            return 0;
        }

        connection.waitForConnection();

        return connection.getPid();
    }

    /**
     * Blocks until the main method invoked by a previous call to launchClient terminates or until
     * the specified time-out expires.
     * Returns immediately if main has already returned.
     * @param pid the process ID that was returned by the call to launchClient
     * @param timeoutMs the timeout in milliseconds after which the method returns even if main has
     *        not returned.
     * @return the return code returned by the main method or whether it timed-out.
     */
    @CalledByNative
    private static MainReturnCodeResult waitForMainToReturn(int pid, int timeoutMs) {
        ClientServiceConnection connection = sConnectionAllocator.getConnectionByPid(pid);
        if (connection == null) {
            Log.e(TAG, "waitForMainToReturn called on unknown connection for pid " + pid);
            return null;
        }
        try {
            return connection.getTestController().waitForMainToReturn(timeoutMs);
        } catch (RemoteException e) {
            Log.e(TAG, "Remote call to waitForMainToReturn failed.");
            return null;
        } finally {
            freeConnection(connection);
        }
    }

    @CalledByNative
    private static boolean terminate(int pid, int exitCode, boolean wait) {
        ClientServiceConnection connection = sConnectionAllocator.getConnectionByPid(pid);
        if (connection == null) {
            Log.e(TAG, "terminate called on unknown connection for pid " + pid);
            return false;
        }
        try {
            if (wait) {
                connection.getTestController().forceStopSynchronous(exitCode);
            } else {
                connection.getTestController().forceStop(exitCode);
            }
        } catch (RemoteException e) {
            // We expect this failure, since the forceStop's service implementation calls
            // System.exit().
        } finally {
            freeConnection(connection);
        }
        return true;
    }

    private static void freeConnection(ClientServiceConnection connection) {
        ContextUtils.getApplicationContext().unbindService(connection);
        sConnectionAllocator.freeConnection(connection);
    }

    /** Does not take ownership of of fds. */
    @CalledByNative
    private static FileDescriptorInfo[] makeFdInfoArray(int[] keys, int[] fds) {
        FileDescriptorInfo[] fdInfos = new FileDescriptorInfo[keys.length];
        for (int i = 0; i < keys.length; i++) {
            FileDescriptorInfo fdInfo = makeFdInfo(keys[i], fds[i]);
            if (fdInfo == null) {
                Log.e(TAG, "Failed to make file descriptor (" + keys[i] + ", " + fds[i] + ").");
                return null;
            }
            fdInfos[i] = fdInfo;
        }
        return fdInfos;
    }

    private static FileDescriptorInfo makeFdInfo(int id, int fd) {
        ParcelFileDescriptor parcelableFd = null;
        try {
            parcelableFd = ParcelFileDescriptor.fromFd(fd);
        } catch (IOException e) {
            Log.e(TAG, "Invalid FD provided for process connection, aborting connection.", e);
            return null;
        }
        return new FileDescriptorInfo(id, parcelableFd, 0 /* offset */, 0 /* size */);
    }
}
