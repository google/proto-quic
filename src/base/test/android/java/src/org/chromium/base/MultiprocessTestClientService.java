// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base;

import android.app.Service;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Parcelable;
import android.os.Process;
import android.os.RemoteException;

import org.chromium.base.annotations.SuppressFBWarnings;
import org.chromium.base.library_loader.LibraryLoader;
import org.chromium.base.library_loader.LibraryProcessType;
import org.chromium.base.library_loader.ProcessInitException;
import org.chromium.base.process_launcher.FileDescriptorInfo;
import org.chromium.base.process_launcher.ICallbackInt;
import org.chromium.base.process_launcher.IChildProcessService;
import org.chromium.native_test.MainRunner;

import javax.annotation.concurrent.GuardedBy;

/**
 * The service implementation used to host all multiprocess test client code.
 */
public class MultiprocessTestClientService extends Service {
    private static final String TAG = "cr_TestClient";

    private static boolean sAlreadyInitialized = false;

    private final Handler mHandler = new Handler();

    private final Object mResultLock = new Object();

    @GuardedBy("mResultLock")
    private MainReturnCodeResult mResult;

    private final ITestController.Stub mTestController = new ITestController.Stub() {
        @SuppressFBWarnings("RCN_REDUNDANT_NULLCHECK_OF_NULL_VALUE")
        @Override
        public MainReturnCodeResult waitForMainToReturn(int timeoutMs) {
            synchronized (mResultLock) {
                while (mResult == null) {
                    try {
                        mResultLock.wait(timeoutMs);
                    } catch (InterruptedException ie) {
                        continue;
                    }
                    // Check if we timed-out.
                    if (mResult == null) {
                        Log.e(TAG, "Failed to wait for main return value.");
                        return new MainReturnCodeResult(0, true /* timed-out */);
                    }
                }
                return mResult;
            }
        }

        @SuppressFBWarnings("DM_EXIT")
        @Override
        public boolean forceStopSynchronous(int exitCode) {
            System.exit(exitCode);
            return true;
        }

        @SuppressFBWarnings("DM_EXIT")
        @Override
        public void forceStop(int exitCode) {
            System.exit(exitCode);
        }
    };

    private final IChildProcessService.Stub mBinder = new IChildProcessService.Stub() {
        @Override
        public boolean bindToCaller() {
            return true;
        }

        @Override
        public void setupConnection(Bundle args, ICallbackInt pidCallback, final IBinder callback) {
            // Required to unparcel FileDescriptorInfo.
            args.setClassLoader(getApplicationContext().getClassLoader());

            final String[] commandLine =
                    args.getStringArray(ChildProcessConstants.EXTRA_COMMAND_LINE);
            final Parcelable[] fdInfosAsParcelable =
                    args.getParcelableArray(ChildProcessConstants.EXTRA_FILES);

            FileDescriptorInfo[] fdsToMap = new FileDescriptorInfo[fdInfosAsParcelable.length];
            System.arraycopy(fdInfosAsParcelable, 0, fdsToMap, 0, fdInfosAsParcelable.length);

            final int[] fdKeys = new int[fdsToMap.length];
            final int[] fdFds = new int[fdsToMap.length];
            for (int i = 0; i < fdsToMap.length; i++) {
                fdKeys[i] = fdsToMap[i].id;
                // Take ownership of the file descriptor so they outlive the FileDescriptorInfo
                // instances. Native code will own them.
                fdFds[i] = fdsToMap[i].fd.detachFd();
            }

            // Prevent potential deadlocks by letting this method return before calling back to the
            // launcher: the childConnected implementation on the launcher side might block until
            // this method returns.
            mHandler.post(new Runnable() {
                @Override
                public void run() {
                    try {
                        ITestCallback testCallback = ITestCallback.Stub.asInterface(callback);
                        testCallback.childConnected(mTestController);
                    } catch (RemoteException re) {
                        Log.e(TAG, "Failed to notify parent process of connection.", re);
                    }
                }
            });

            // Don't run main directly, it would block and the response would not be returned.
            // We post to the main thread as this thread does not have a Looper.
            mHandler.post(new Runnable() {
                @Override
                public void run() {
                    int result = MainRunner.runMain(commandLine, fdKeys, fdFds);
                    setMainReturnValue(result);
                }
            });

            try {
                pidCallback.call(Process.myPid());
            } catch (RemoteException re) {
                Log.e(TAG, "Service failed to report PID to launcher.", re);
            }
        }

        @Override
        public void crashIntentionallyForTesting() {
            assert false : "crashIntentionallyForTesting not implemented.";
        }
    };

    @SuppressFBWarnings("DM_EXIT")
    @Override
    public void onCreate() {
        super.onCreate();

        if (sAlreadyInitialized) {
            // The framework controls how services are reused and even though nothing is bound to a
            // service it might be kept around. Since we really want to fork a new process when we
            // bind, we'll kill the process early when a service is reused, forcing the framework to
            // recreate the service in a new process.
            // This is not ideal, but there are no clear alternatives at this point.
            Log.e(TAG, "Service being reused, forcing stoppage.");
            System.exit(0);
            return;
        }
        markInitialized();

        ContextUtils.initApplicationContext(getApplicationContext());

        PathUtils.setPrivateDataDirectorySuffix("chrome_multiprocess_test_client_service");

        loadLibraries();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return mBinder;
    }

    private void loadLibraries() {
        try {
            LibraryLoader.get(LibraryProcessType.PROCESS_CHILD).loadNow();
        } catch (ProcessInitException pie) {
            Log.e(TAG, "Unable to load native libraries.", pie);
        }
    }

    private void setMainReturnValue(int result) {
        synchronized (mResultLock) {
            mResult = new MainReturnCodeResult(result, false /* timed-out */);
            mResultLock.notifyAll();
        }
    }

    private static void markInitialized() {
        // We don't set sAlreadyInitialized directly in onCreate to avoid FindBugs complaining about
        // a static member been set from a non-static function.
        sAlreadyInitialized = true;
    }
}
