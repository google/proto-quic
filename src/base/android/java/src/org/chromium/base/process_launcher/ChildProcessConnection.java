// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base.process_launcher;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.RemoteException;
import android.os.SystemClock;

import org.chromium.base.Log;
import org.chromium.base.TraceEvent;
import org.chromium.base.VisibleForTesting;
import org.chromium.base.metrics.CachedMetrics;

import java.util.concurrent.TimeUnit;

import javax.annotation.Nullable;

/**
 * Manages a connection between the browser activity and a child service.
 */
public class ChildProcessConnection {
    private static final String TAG = "ChildProcessConn";

    private static final int BIND_SERVICE_TIMEOUT_IN_MS = 10 * 1000;

    /**
     * Used to notify the consumer about the process start. These callbacks will be invoked before
     * the ConnectionCallbacks.
     */
    public interface ServiceCallback {
        /**
         * Called when the child process has successfully started and is ready for connection
         * setup.
         */
        void onChildStarted();

        /**
         * Called when the child process failed to start. This can happen if the process is already
         * in use by another client. Note onChildProcessDied will be called after this callback,
         * once the client unbinds and the service gets cleaned.
         * TODO(jcivelli): crbug.com/736948 we should improve the behavior in such cases.
         */
        void onChildStartFailed();

        /**
         * Called when the service has been disconnected. whether it was stopped by the client or
         * if it stopped unexpectedly (process crash).
         * This is the last callback from this interface that a client will receive for a specific
         * connection.
         */
        void onChildProcessDied(ChildProcessConnection connection);
    }

    /**
     * Used to notify the consumer about the connection being established.
     */
    public interface ConnectionCallback {
        /**
         * Called when the connection to the service is established.
         * @param connection the connection object to the child process
         */
        void onConnected(ChildProcessConnection connection);
    }

    /**
     * Delegate that ChildServiceConnection should call when the service connects/disconnects.
     * These callbacks are expected to happen on a background thread.
     */
    @VisibleForTesting
    protected interface ChildServiceConnectionDelegate {
        void onServiceConnected(IBinder service);
        void onServiceDisconnected();
    }

    @VisibleForTesting
    protected interface ChildServiceConnectionFactory {
        ChildServiceConnection createConnection(
                Intent bindIntent, int bindFlags, ChildServiceConnectionDelegate delegate);
    }

    /** Interface representing a connection to the Android service. Can be mocked in unit-tests. */
    @VisibleForTesting
    protected interface ChildServiceConnection {
        boolean bind();
        void unbind();
        boolean isBound();
    }

    /** Implementation of ChildServiceConnection that does connect to a service. */
    private static class ChildServiceConnectionImpl
            implements ChildServiceConnection, ServiceConnection {
        private final Context mContext;
        private final Intent mBindIntent;
        private final int mBindFlags;
        private final ChildServiceConnectionDelegate mDelegate;
        private boolean mBound;

        private ChildServiceConnectionImpl(Context context, Intent bindIntent, int bindFlags,
                ChildServiceConnectionDelegate delegate) {
            mContext = context;
            mBindIntent = bindIntent;
            mBindFlags = bindFlags;
            mDelegate = delegate;
        }

        @Override
        public boolean bind() {
            if (!mBound) {
                try {
                    TraceEvent.begin("ChildProcessConnection.ChildServiceConnectionImpl.bind");
                    mBound = mContext.bindService(mBindIntent, this, mBindFlags);
                } finally {
                    TraceEvent.end("ChildProcessConnection.ChildServiceConnectionImpl.bind");
                }
            }
            return mBound;
        }

        @Override
        public void unbind() {
            if (mBound) {
                mContext.unbindService(this);
                mBound = false;
            }
        }

        @Override
        public boolean isBound() {
            return mBound;
        }

        @Override
        public void onServiceConnected(ComponentName className, final IBinder service) {
            mDelegate.onServiceConnected(service);
        }

        // Called on the main thread to notify that the child service did not disconnect gracefully.
        @Override
        public void onServiceDisconnected(ComponentName className) {
            mDelegate.onServiceDisconnected();
        }
    }

    // CachedMetrics used from this class, because this class can run before native library is
    // loaded.
    private static final CachedMetrics.TimesHistogramSample sOnServiceConnectedTimesMetric =
            new CachedMetrics.TimesHistogramSample(
                    "Android.ChildProcessLauncher.OnServiceConnectedTime", TimeUnit.MILLISECONDS);
    private static final CachedMetrics
            .BooleanHistogramSample sOnServiceConnectedTimesMetricTimedOut =
            new CachedMetrics.BooleanHistogramSample(
                    "Android.ChildProcessLauncher.OnServiceConnectedTimedOut");

    private final Handler mLauncherHandler;
    private final ComponentName mServiceName;

    // Parameters passed to the child process through the service binding intent.
    // If the service gets recreated by the framework the intent will be reused, so these parameters
    // should be common to all processes of that type.
    private final Bundle mServiceBundle;

    // Whether bindToCaller should be called on the service after setup to check that only one
    // process is bound to the service.
    private final boolean mBindToCaller;

    private static class ConnectionParams {
        final Bundle mConnectionBundle;
        final IBinder mCallback;

        ConnectionParams(Bundle connectionBundle, IBinder callback) {
            mConnectionBundle = connectionBundle;
            mCallback = callback;
        }
    }

    // This is set in start() and is used in onServiceConnected().
    private ServiceCallback mServiceCallback;

    // This is set in setupConnection() and is later used in doConnectionSetup(), after which the
    // variable is cleared. Therefore this is only valid while the connection is being set up.
    private ConnectionParams mConnectionParams;

    // Callback provided in setupConnection() that will communicate the result to the caller. This
    // has to be called exactly once after setupConnection(), even if setup fails, so that the
    // caller can free up resources associated with the setup attempt. This is set to null after the
    // call.
    private ConnectionCallback mConnectionCallback;

    // Workaround bug on some android versions where bindService does not result in
    // onServiceConnected for sandboxed services; see crbug.com/736066 for details.
    // This is a delayed callback that will retry bindService with a delay.
    private Runnable mOnServiceConnectedWatchDog;

    private IChildProcessService mService;

    // Set to true when the service connection callback runs. This differs from
    // mServiceConnectComplete, which tracks that the connection completed successfully.
    private boolean mDidOnServiceConnected;

    // Set to true when the service connected successfully.
    private boolean mServiceConnectComplete;

    // Set to true when the service disconnects, as opposed to being properly closed. This happens
    // when the process crashes or gets killed by the system out-of-memory killer.
    private boolean mServiceDisconnected;

    // Process ID of the corresponding child process.
    private int mPid;

    // Inital moderate binding.
    private final ChildServiceConnection mInitialBinding;

    // Strong binding will make the service priority equal to the priority of the activity.
    private final ChildServiceConnection mStrongBinding;

    // Moderate binding will make the service priority equal to the priority of a visible process
    // while the app is in the foreground.
    private final ChildServiceConnection mModerateBinding;

    // Low priority binding maintained in the entire lifetime of the connection, i.e. between calls
    // to start() and stop().
    private final ChildServiceConnection mWaivedBinding;

    // Incremented on addStrongBinding(), decremented on removeStrongBinding().
    private int mStrongBindingCount;

    // Indicates whether the connection only has the waived binding (if the connection is unbound,
    // it contains the state at time of unbinding).
    private boolean mWaivedBoundOnly;

    // Set to true once unbind() was called.
    private boolean mUnbound;

    // Timestamp when watchdog was last reset, which is equivalent to when start was called.
    private long mLastWatchdogResetTimestamp;

    public ChildProcessConnection(Context context, ComponentName serviceName, boolean bindToCaller,
            boolean bindAsExternalService, Bundle serviceBundle) {
        this(context, serviceName, bindToCaller, bindAsExternalService, serviceBundle,
                null /* connectionFactory */);
    }

    @VisibleForTesting
    public ChildProcessConnection(final Context context, ComponentName serviceName,
            boolean bindToCaller, boolean bindAsExternalService, Bundle serviceBundle,
            ChildServiceConnectionFactory connectionFactory) {
        mLauncherHandler = new Handler();
        assert isRunningOnLauncherThread();
        mServiceName = serviceName;
        mServiceBundle = serviceBundle != null ? serviceBundle : new Bundle();
        mServiceBundle.putBoolean(ChildProcessConstants.EXTRA_BIND_TO_CALLER, bindToCaller);
        mBindToCaller = bindToCaller;

        if (connectionFactory == null) {
            connectionFactory = new ChildServiceConnectionFactory() {
                @Override
                public ChildServiceConnection createConnection(
                        Intent bindIntent, int bindFlags, ChildServiceConnectionDelegate delegate) {
                    return new ChildServiceConnectionImpl(context, bindIntent, bindFlags, delegate);
                }
            };
        }

        ChildServiceConnectionDelegate delegate = new ChildServiceConnectionDelegate() {
            @Override
            public void onServiceConnected(final IBinder service) {
                mLauncherHandler.post(new Runnable() {
                    @Override
                    public void run() {
                        onServiceConnectedOnLauncherThread(service);
                    }
                });
            }

            @Override
            public void onServiceDisconnected() {
                mLauncherHandler.post(new Runnable() {
                    @Override
                    public void run() {
                        onServiceDisconnectedOnLauncherThread();
                    }
                });
            }
        };

        Intent intent = new Intent();
        intent.setComponent(serviceName);
        if (serviceBundle != null) {
            intent.putExtras(serviceBundle);
        }

        int defaultFlags = Context.BIND_AUTO_CREATE
                | (bindAsExternalService ? Context.BIND_EXTERNAL_SERVICE : 0);

        mInitialBinding = connectionFactory.createConnection(intent, defaultFlags, delegate);
        mModerateBinding = connectionFactory.createConnection(intent, defaultFlags, delegate);
        mStrongBinding = connectionFactory.createConnection(
                intent, defaultFlags | Context.BIND_IMPORTANT, delegate);
        mWaivedBinding = connectionFactory.createConnection(
                intent, defaultFlags | Context.BIND_WAIVE_PRIORITY, delegate);
    }

    public final IChildProcessService getService() {
        assert isRunningOnLauncherThread();
        return mService;
    }

    public final ComponentName getServiceName() {
        assert isRunningOnLauncherThread();
        return mServiceName;
    }

    public boolean isConnected() {
        return mService != null;
    }

    /**
     * @return the connection pid, or 0 if not yet connected
     */
    public int getPid() {
        assert isRunningOnLauncherThread();
        return mPid;
    }

    /**
     * Starts a connection to an IChildProcessService. This must be followed by a call to
     * setupConnection() to setup the connection parameters. start() and setupConnection() are
     * separate to allow to pass whatever parameters are available in start(), and complete the
     * remainder addStrongBinding while reducing the connection setup latency.
     * @param useStrongBinding whether a strong binding should be bound by default. If false, an
     * initial moderate binding is used.
     * @param serviceCallback (optional) callbacks invoked when the child process starts or fails to
     * start and when the service stops.
     */
    public void start(
            boolean useStrongBinding, ServiceCallback serviceCallback, boolean retryOnTimeout) {
        try {
            TraceEvent.begin("ChildProcessConnection.start");
            assert isRunningOnLauncherThread();
            assert mConnectionParams
                    == null : "setupConnection() called before start() in ChildProcessConnection.";

            mServiceCallback = serviceCallback;

            resetWatchdog(useStrongBinding, serviceCallback, retryOnTimeout);
            if (!bind(useStrongBinding)) {
                Log.e(TAG, "Failed to establish the service connection.");
                cancelWatchDog();
                // We have to notify the caller so that they can free-up associated resources.
                // TODO(ppi): Can we hard-fail here?
                notifyChildProcessDied();
            }
        } finally {
            TraceEvent.end("ChildProcessConnection.start");
        }
    }

    /**
     * Sets-up the connection after it was started with start().
     * @param connectionBundle a bundle passed to the service that can be used to pass various
     *         parameters to the service
     * @param callback optional client specified callbacks that the child can use to communicate
     *                 with the parent process
     * @param connectionCallback will be called exactly once after the connection is set up or the
     *                           setup fails
     */
    public void setupConnection(Bundle connectionBundle, @Nullable IBinder callback,
            ConnectionCallback connectionCallback) {
        assert isRunningOnLauncherThread();
        assert mConnectionParams == null;
        if (mServiceDisconnected) {
            Log.w(TAG, "Tried to setup a connection that already disconnected.");
            connectionCallback.onConnected(null);
            return;
        }
        try {
            TraceEvent.begin("ChildProcessConnection.setupConnection");
            mConnectionCallback = connectionCallback;
            mConnectionParams = new ConnectionParams(connectionBundle, callback);
            // Run the setup if the service is already connected. If not, doConnectionSetup() will
            // be called from onServiceConnected().
            if (mServiceConnectComplete) {
                doConnectionSetup();
            }
        } finally {
            TraceEvent.end("ChildProcessConnection.setupConnection");
        }
    }

    /**
     * Terminates the connection to IChildProcessService, closing all bindings. It is safe to call
     * this multiple times.
     */
    public void stop() {
        assert isRunningOnLauncherThread();
        cancelWatchDog();
        unbind();
        mService = null;
        mConnectionParams = null;
        notifyChildProcessDied();
    }

    @VisibleForTesting
    public void onServiceConnectedOnLauncherThread(IBinder service) {
        assert isRunningOnLauncherThread();
        cancelWatchDog();
        // A flag from the parent class ensures we run the post-connection logic only once
        // (instead of once per each ChildServiceConnection).
        if (mDidOnServiceConnected) {
            return;
        }
        try {
            TraceEvent.begin("ChildProcessConnection.ChildServiceConnection.onServiceConnected");
            sOnServiceConnectedTimesMetric.record(
                    SystemClock.elapsedRealtime() - mLastWatchdogResetTimestamp);
            sOnServiceConnectedTimesMetricTimedOut.record(false);

            mDidOnServiceConnected = true;
            mService = IChildProcessService.Stub.asInterface(service);

            if (mBindToCaller) {
                try {
                    if (!mService.bindToCaller()) {
                        if (mServiceCallback != null) {
                            mServiceCallback.onChildStartFailed();
                        }
                        return;
                    }
                } catch (RemoteException ex) {
                    // Do not trigger the StartCallback here, since the service is already
                    // dead and the onChildStopped callback will run from onServiceDisconnected().
                    Log.e(TAG, "Failed to bind service to connection.", ex);
                    return;
                }
            }

            if (mServiceCallback != null) {
                mServiceCallback.onChildStarted();
            }

            mServiceConnectComplete = true;

            // Run the setup if the connection parameters have already been provided. If
            // not, doConnectionSetup() will be called from setupConnection().
            if (mConnectionParams != null) {
                doConnectionSetup();
            }
        } finally {
            TraceEvent.end("ChildProcessConnection.ChildServiceConnection.onServiceConnected");
        }
    }

    private void onServiceDisconnectedOnLauncherThread() {
        assert isRunningOnLauncherThread();
        // Ensure that the disconnection logic runs only once (instead of once per each
        // ChildServiceConnection).
        if (mServiceDisconnected) {
            return;
        }
        mServiceDisconnected = true;
        Log.w(TAG, "onServiceDisconnected (crash or killed by oom): pid=%d", mPid);
        stop(); // We don't want to auto-restart on crash. Let the browser do that.

        // If we have a pending connection callback, we need to communicate the failure to
        // the caller.
        if (mConnectionCallback != null) {
            mConnectionCallback.onConnected(null);
            mConnectionCallback = null;
        }
    }

    private void onSetupConnectionResult(int pid) {
        mPid = pid;
        assert mPid != 0 : "Child service claims to be run by a process of pid=0.";

        if (mConnectionCallback != null) {
            mConnectionCallback.onConnected(this);
        }
        mConnectionCallback = null;
    }

    /**
     * Called after the connection parameters have been set (in setupConnection()) *and* a
     * connection has been established (as signaled by onServiceConnected()). These two events can
     * happen in any order.
     */
    private void doConnectionSetup() {
        try {
            TraceEvent.begin("ChildProcessConnection.doConnectionSetup");
            assert mServiceConnectComplete && mService != null;
            assert mConnectionParams != null;

            ICallbackInt pidCallback = new ICallbackInt.Stub() {
                @Override
                public void call(final int pid) {
                    mLauncherHandler.post(new Runnable() {
                        @Override
                        public void run() {
                            onSetupConnectionResult(pid);
                        }
                    });
                }
            };
            try {
                mService.setupConnection(mConnectionParams.mConnectionBundle, pidCallback,
                        mConnectionParams.mCallback);
            } catch (RemoteException re) {
                Log.e(TAG, "Failed to setup connection.", re);
            }
            mConnectionParams = null;
        } finally {
            TraceEvent.end("ChildProcessConnection.doConnectionSetup");
        }
    }

    private boolean bind(boolean useStrongBinding) {
        assert isRunningOnLauncherThread();
        assert !mUnbound;

        boolean success = useStrongBinding ? mStrongBinding.bind() : mInitialBinding.bind();
        if (!success) return false;

        updateWaivedBoundOnlyState();
        mWaivedBinding.bind();
        return true;
    }

    @VisibleForTesting
    protected void unbind() {
        assert isRunningOnLauncherThread();
        mUnbound = true;
        unbindAll();
        // Note that we don't update the waived bound only state here as to preserve the state when
        // disconnected.
    }

    private void unbindAll() {
        mStrongBinding.unbind();
        mWaivedBinding.unbind();
        mModerateBinding.unbind();
        mInitialBinding.unbind();
    }

    public boolean isInitialBindingBound() {
        assert isRunningOnLauncherThread();
        return mInitialBinding.isBound();
    }

    public void addInitialBinding() {
        assert isRunningOnLauncherThread();
        mInitialBinding.bind();
        updateWaivedBoundOnlyState();
    }

    public boolean isStrongBindingBound() {
        assert isRunningOnLauncherThread();
        return mStrongBinding.isBound();
    }

    public void removeInitialBinding() {
        assert isRunningOnLauncherThread();
        mInitialBinding.unbind();
        updateWaivedBoundOnlyState();
    }

    public void dropOomBindings() {
        assert isRunningOnLauncherThread();
        mInitialBinding.unbind();

        mStrongBindingCount = 0;
        mStrongBinding.unbind();
        updateWaivedBoundOnlyState();

        mModerateBinding.unbind();
    }

    public void addStrongBinding() {
        assert isRunningOnLauncherThread();
        if (!isConnected()) {
            Log.w(TAG, "The connection is not bound for %d", getPid());
            return;
        }
        if (mStrongBindingCount == 0) {
            mStrongBinding.bind();
            updateWaivedBoundOnlyState();
        }
        mStrongBindingCount++;
    }

    public void removeStrongBinding() {
        assert isRunningOnLauncherThread();
        if (!isConnected()) {
            Log.w(TAG, "The connection is not bound for %d", getPid());
            return;
        }
        assert mStrongBindingCount > 0;
        mStrongBindingCount--;
        if (mStrongBindingCount == 0) {
            mStrongBinding.unbind();
            updateWaivedBoundOnlyState();
        }
    }

    public boolean isModerateBindingBound() {
        assert isRunningOnLauncherThread();
        return mModerateBinding.isBound();
    }

    public void addModerateBinding() {
        assert isRunningOnLauncherThread();
        if (!isConnected()) {
            Log.w(TAG, "The connection is not bound for %d", getPid());
            return;
        }
        mModerateBinding.bind();
        updateWaivedBoundOnlyState();
    }

    public void removeModerateBinding() {
        assert isRunningOnLauncherThread();
        if (!isConnected()) {
            Log.w(TAG, "The connection is not bound for %d", getPid());
            return;
        }
        mModerateBinding.unbind();
        updateWaivedBoundOnlyState();
    }

    /**
     * @return true if the connection is bound and only bound with the waived binding or if the
     * connection is unbound and was only bound with the waived binding when it disconnected.
     */
    public boolean isWaivedBoundOnlyOrWasWhenDied() {
        // WARNING: this method can be called from a thread other than the launcher thread.
        // Note that it returns the current waived bound only state and is racy. This not really
        // preventable without changing the caller's API, short of blocking.
        return mWaivedBoundOnly;
    }

    // Should be called every time the mInitialBinding or mStrongBinding are bound/unbound.
    private void updateWaivedBoundOnlyState() {
        if (!mUnbound) {
            mWaivedBoundOnly = !mInitialBinding.isBound() && !mStrongBinding.isBound()
                    && !mModerateBinding.isBound();
        }
    }

    private void notifyChildProcessDied() {
        if (mServiceCallback != null) {
            // Guard against nested calls to this method.
            ServiceCallback serviceCallback = mServiceCallback;
            mServiceCallback = null;
            serviceCallback.onChildProcessDied(this);
        }
    }

    private void resetWatchdog(final boolean useStrongBinding,
            final ServiceCallback serviceCallback, final boolean retryOnTimeout) {
        assert isRunningOnLauncherThread();
        cancelWatchDog();
        assert mOnServiceConnectedWatchDog == null;
        mOnServiceConnectedWatchDog = new Runnable() {
            @Override
            public void run() {
                assert mOnServiceConnectedWatchDog == this;
                assert !mDidOnServiceConnected;
                assert mServiceCallback == null;
                mOnServiceConnectedWatchDog = null;
                sOnServiceConnectedTimesMetricTimedOut.record(true);
                if (!retryOnTimeout) return;
                unbindAll();
                start(useStrongBinding, serviceCallback, retryOnTimeout);
            }
        };
        mLastWatchdogResetTimestamp = SystemClock.elapsedRealtime();
        mLauncherHandler.postDelayed(mOnServiceConnectedWatchDog, BIND_SERVICE_TIMEOUT_IN_MS);
    }

    private void cancelWatchDog() {
        assert isRunningOnLauncherThread();
        if (mOnServiceConnectedWatchDog == null) return;
        mLauncherHandler.removeCallbacks(mOnServiceConnectedWatchDog);
        mOnServiceConnectedWatchDog = null;
    }

    private boolean isRunningOnLauncherThread() {
        return mLauncherHandler.getLooper() == Looper.myLooper();
    }

    @VisibleForTesting
    public void crashServiceForTesting() throws RemoteException {
        mService.crashIntentionallyForTesting();
    }

    @VisibleForTesting
    public boolean didOnServiceConnectedForTesting() {
        return mDidOnServiceConnected;
    }

    @VisibleForTesting
    protected Handler getLauncherHandler() {
        return mLauncherHandler;
    }
}
