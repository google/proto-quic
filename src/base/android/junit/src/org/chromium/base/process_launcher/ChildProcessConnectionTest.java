// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base.process_launcher;

import android.content.ComponentName;
import android.content.Intent;
import android.os.Binder;
import android.os.Bundle;
import android.os.IBinder;
import android.os.RemoteException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.AdditionalMatchers.or;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowLooper;

import org.chromium.testing.local.LocalRobolectricTestRunner;

/** Unit tests for ChildProcessConnection. */
@RunWith(LocalRobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class ChildProcessConnectionTest {
    private static class ChildServiceConnectionMock
            implements ChildProcessConnection.ChildServiceConnection {
        private final Intent mBindIntent;
        private final ChildProcessConnection.ChildServiceConnectionDelegate mDelegate;
        private boolean mBound;

        public ChildServiceConnectionMock(
                Intent bindIntent, ChildProcessConnection.ChildServiceConnectionDelegate delegate) {
            mBindIntent = bindIntent;
            mDelegate = delegate;
        }

        @Override
        public boolean bind() {
            mBound = true;
            return true;
        }

        @Override
        public void unbind() {
            mBound = false;
        }

        @Override
        public boolean isBound() {
            return mBound;
        }

        public void notifyServiceConnected(IBinder service) {
            mDelegate.onServiceConnected(service);
        }

        public void notifyServiceDisconnected() {
            mDelegate.onServiceDisconnected();
        }

        public Intent getBindIntent() {
            return mBindIntent;
        }
    };

    private final ChildProcessConnection.ChildServiceConnectionFactory mServiceConnectionFactory =
            new ChildProcessConnection.ChildServiceConnectionFactory() {
                public ChildProcessConnection.ChildServiceConnection createConnection(
                        Intent bindIntent, int bindFlags,
                        ChildProcessConnection.ChildServiceConnectionDelegate delegate) {
                    ChildServiceConnectionMock connection =
                            spy(new ChildServiceConnectionMock(bindIntent, delegate));
                    if (mFirstServiceConnection == null) {
                        mFirstServiceConnection = connection;
                    }
                    return connection;
                }
            };

    @Mock
    private ChildProcessConnection.ServiceCallback mServiceCallback;

    @Mock
    private ChildProcessConnection.ConnectionCallback mConnectionCallback;

    private IChildProcessService mIChildProcessService;

    private Binder mChildProcessServiceBinder;

    private ChildServiceConnectionMock mFirstServiceConnection;

    // Parameters captured from the IChildProcessService.setupConnection() call
    private Bundle mConnectionBundle;
    private ICallbackInt mConnectionPidCallback;
    private IBinder mConnectionIBinderCallback;

    @Before
    public void setUp() throws RemoteException {
        MockitoAnnotations.initMocks(this);

        mIChildProcessService = mock(IChildProcessService.class);
        // Capture the parameters passed to the IChildProcessService.setupConnection() call.
        doAnswer(new Answer<Void>() {
            @Override
            public Void answer(InvocationOnMock invocation) {
                mConnectionBundle = (Bundle) invocation.getArgument(0);
                mConnectionPidCallback = (ICallbackInt) invocation.getArgument(1);
                mConnectionIBinderCallback = (IBinder) invocation.getArgument(2);
                return null;
            }
        })
                .when(mIChildProcessService)
                .setupConnection(or(isNull(), any(Bundle.class)),
                        or(isNull(), any(ICallbackInt.class)), or(isNull(), any(IBinder.class)));

        mChildProcessServiceBinder = new Binder();
        mChildProcessServiceBinder.attachInterface(
                mIChildProcessService, IChildProcessService.class.getName());
    }

    private ChildProcessConnection createDefaultTestConnection() {
        return createTestConnection(false /* bindToCaller */, false /* bindAsExternalService */,
                null /* serviceBundle */);
    }

    private ChildProcessConnection createTestConnection(
            boolean bindToCaller, boolean bindAsExternalService, Bundle serviceBundle) {
        String packageName = "org.chromium.test";
        String serviceName = "TestService";
        return new ChildProcessConnection(null /* context */,
                new ComponentName(packageName, serviceName), bindToCaller, bindAsExternalService,
                serviceBundle, mServiceConnectionFactory);
    }

    @Test
    public void testStrongBinding() {
        ChildProcessConnection connection = createDefaultTestConnection();
        connection.start(true /* useStrongBinding */, null /* serviceCallback */,
                false /* retryOnTimeout */);
        assertTrue(connection.isStrongBindingBound());

        connection = createDefaultTestConnection();
        connection.start(false /* useStrongBinding */, null /* serviceCallback */,
                false /* retryOnTimeout */);
        assertFalse(connection.isStrongBindingBound());
    }

    @Test
    public void testServiceBundle() {
        Bundle serviceBundle = new Bundle();
        final String intKey = "org.chromium.myInt";
        final int intValue = 34;
        final int defaultValue = -1;
        serviceBundle.putInt(intKey, intValue);
        String stringKey = "org.chromium.myString";
        String stringValue = "thirty four";
        serviceBundle.putString(stringKey, stringValue);

        ChildProcessConnection connection = createTestConnection(
                false /* bindToCaller */, false /* bindAsExternalService */, serviceBundle);
        // Start the connection without the ChildServiceConnection connecting.
        connection.start(false /* useStrongBinding */, null /* serviceCallback */,
                true /* retryOnTimeout */);
        assertNotNull(mFirstServiceConnection);
        Intent bindIntent = mFirstServiceConnection.getBindIntent();
        assertNotNull(bindIntent);
        assertEquals(intValue, bindIntent.getIntExtra(intKey, defaultValue));
        assertEquals(stringValue, bindIntent.getStringExtra(stringKey));
    }

    @Test
    public void testServiceStartsSuccessfully() {
        ChildProcessConnection connection = createDefaultTestConnection();
        assertNotNull(mFirstServiceConnection);
        connection.start(false /* useStrongBinding */, mServiceCallback, true /* retryOnTimeout */);
        Assert.assertTrue(connection.isInitialBindingBound());
        Assert.assertFalse(connection.didOnServiceConnectedForTesting());
        verify(mServiceCallback, never()).onChildStarted();
        verify(mServiceCallback, never()).onChildStartFailed();
        verify(mServiceCallback, never()).onChildProcessDied(any());

        // The service connects.
        mFirstServiceConnection.notifyServiceConnected(null /* iBinder */);
        Assert.assertTrue(connection.didOnServiceConnectedForTesting());
        verify(mServiceCallback, times(1)).onChildStarted();
        verify(mServiceCallback, never()).onChildStartFailed();
        verify(mServiceCallback, never()).onChildProcessDied(any());
    }

    @Test
    public void testServiceStartsAndFailsToBind() {
        ChildProcessConnection connection = createDefaultTestConnection();
        assertNotNull(mFirstServiceConnection);
        // Note we use doReturn so the actual bind() method is not called (it would with
        // when(mFirstServiceConnection.bind()).thenReturn(false).
        doReturn(false).when(mFirstServiceConnection).bind();
        connection.start(false /* useStrongBinding */, mServiceCallback, true /* retryOnTimeout */);

        Assert.assertFalse(connection.isInitialBindingBound());
        Assert.assertFalse(connection.didOnServiceConnectedForTesting());
        verify(mServiceCallback, never()).onChildStarted();
        verify(mServiceCallback, never()).onChildStartFailed();
        verify(mServiceCallback, times(1)).onChildProcessDied(connection);
    }

    @Test
    public void testServiceStops() {
        ChildProcessConnection connection = createDefaultTestConnection();
        assertNotNull(mFirstServiceConnection);
        connection.start(false /* useStrongBinding */, mServiceCallback, true /* retryOnTimeout */);
        mFirstServiceConnection.notifyServiceConnected(null /* iBinder */);
        connection.stop();
        verify(mServiceCallback, times(1)).onChildStarted();
        verify(mServiceCallback, never()).onChildStartFailed();
        verify(mServiceCallback, times(1)).onChildProcessDied(connection);
    }

    @Test
    public void testServiceDisconnects() {
        ChildProcessConnection connection = createDefaultTestConnection();
        assertNotNull(mFirstServiceConnection);
        connection.start(false /* useStrongBinding */, mServiceCallback, true /* retryOnTimeout */);
        mFirstServiceConnection.notifyServiceConnected(null /* iBinder */);
        mFirstServiceConnection.notifyServiceDisconnected();
        verify(mServiceCallback, times(1)).onChildStarted();
        verify(mServiceCallback, never()).onChildStartFailed();
        verify(mServiceCallback, times(1)).onChildProcessDied(connection);
    }

    @Test
    public void testNotBoundToCaller() throws RemoteException {
        ChildProcessConnection connection = createTestConnection(false /* bindToCaller */,
                false /* bindAsExternalService */, null /* serviceBundle */);
        assertNotNull(mFirstServiceConnection);
        connection.start(false /* useStrongBinding */, mServiceCallback, true /* retryOnTimeout */);
        mFirstServiceConnection.notifyServiceConnected(mChildProcessServiceBinder);
        // Service is started and bindToCallback is not called.
        verify(mServiceCallback, times(1)).onChildStarted();
        verify(mServiceCallback, never()).onChildStartFailed();
        verify(mServiceCallback, never()).onChildProcessDied(connection);
        verify(mIChildProcessService, never()).bindToCaller();
    }

    @Test
    public void testBoundToCallerSuccess() throws RemoteException {
        ChildProcessConnection connection = createTestConnection(true /* bindToCaller */,
                false /* bindAsExternalService */, null /* serviceBundle */);
        assertNotNull(mFirstServiceConnection);
        connection.start(false /* useStrongBinding */, mServiceCallback, true /* retryOnTimeout */);
        when(mIChildProcessService.bindToCaller()).thenReturn(true);
        mFirstServiceConnection.notifyServiceConnected(mChildProcessServiceBinder);
        // Service is started and bindToCallback is called.
        verify(mServiceCallback, times(1)).onChildStarted();
        verify(mServiceCallback, never()).onChildStartFailed();
        verify(mServiceCallback, never()).onChildProcessDied(connection);
        verify(mIChildProcessService, times(1)).bindToCaller();
    }

    @Test
    public void testBoundToCallerFailure() throws RemoteException {
        ChildProcessConnection connection = createTestConnection(true /* bindToCaller */,
                false /* bindAsExternalService */, null /* serviceBundle */);
        assertNotNull(mFirstServiceConnection);
        connection.start(false /* useStrongBinding */, mServiceCallback, true /* retryOnTimeout */);
        // Pretend bindToCaller returns false, i.e. the service is already bound to a different
        // service.
        when(mIChildProcessService.bindToCaller()).thenReturn(false);
        mFirstServiceConnection.notifyServiceConnected(mChildProcessServiceBinder);
        // Service fails to start.
        verify(mServiceCallback, never()).onChildStarted();
        verify(mServiceCallback, times(1)).onChildStartFailed();
        verify(mServiceCallback, never()).onChildProcessDied(connection);
        verify(mIChildProcessService, times(1)).bindToCaller();
    }

    @Test
    public void testSetupConnectionBeforeServiceConnected() throws RemoteException {
        ChildProcessConnection connection = createDefaultTestConnection();
        assertNotNull(mFirstServiceConnection);
        connection.start(false /* useStrongBinding */, null /* serviceCallback */,
                true /* retryOnTimeout */);
        connection.setupConnection(
                null /* connectionBundle */, null /* callback */, mConnectionCallback);
        verify(mConnectionCallback, never()).onConnected(any());
        mFirstServiceConnection.notifyServiceConnected(mChildProcessServiceBinder);
        ShadowLooper.runUiThreadTasks();
        assertNotNull(mConnectionPidCallback);
        mConnectionPidCallback.call(34 /* pid */);
        verify(mConnectionCallback, times(1)).onConnected(connection);
    }

    @Test
    public void testSetupConnectionAfterServiceConnected() throws RemoteException {
        ChildProcessConnection connection = createDefaultTestConnection();
        assertNotNull(mFirstServiceConnection);
        connection.start(false /* useStrongBinding */, null /* serviceCallback */,
                true /* retryOnTimeout */);
        mFirstServiceConnection.notifyServiceConnected(mChildProcessServiceBinder);
        connection.setupConnection(
                null /* connectionBundle */, null /* callback */, mConnectionCallback);
        verify(mConnectionCallback, never()).onConnected(any());
        ShadowLooper.runUiThreadTasks();
        assertNotNull(mConnectionPidCallback);
        mConnectionPidCallback.call(34 /* pid */);
        verify(mConnectionCallback, times(1)).onConnected(connection);
    }

    @Test
    public void testWatchdog() {
        ChildProcessConnection connection = createDefaultTestConnection();
        // Start the connection without the ChildServiceConnection connecting.
        connection.start(false /* useStrongBinding */, null /* serviceCallback */,
                true /* retryOnTimeout */);
        assertNotNull(mFirstServiceConnection);
        verify(mFirstServiceConnection, times(1)).bind();
        Assert.assertTrue(connection.isInitialBindingBound());

        ShadowLooper.runUiThreadTasksIncludingDelayedTasks();
        // The watchdog should have attempted to reconnect.
        Assert.assertTrue(connection.isInitialBindingBound());
        verify(mFirstServiceConnection, times(1)).unbind();
        verify(mFirstServiceConnection, times(2)).bind();
    }

    @Test
    public void testWatchdogDisabled() {
        ChildProcessConnection connection = createDefaultTestConnection();
        connection.start(false /* useStrongBinding */, null /* serviceCallback */,
                false /* retryOnTimeout */);
        assertNotNull(mFirstServiceConnection);
        verify(mFirstServiceConnection, times(1)).bind();
        Assert.assertTrue(connection.isInitialBindingBound());

        ShadowLooper.runUiThreadTasksIncludingDelayedTasks();
        // No retry should have been attempted.
        Assert.assertTrue(connection.isInitialBindingBound());
        verify(mFirstServiceConnection, never()).unbind();
        verify(mFirstServiceConnection, times(1)).bind();
    }

    @Test
    public void testWatchdogCancelledOnConnection() {
        ChildProcessConnection connection = createDefaultTestConnection();
        connection.start(false /* useStrongBinding */, null /* serviceCallback */,
                true /* retryOnTimeout */);
        assertNotNull(mFirstServiceConnection);
        ShadowLooper.runUiThreadTasksIncludingDelayedTasks();
        Assert.assertTrue(connection.isInitialBindingBound());
        Assert.assertFalse(connection.didOnServiceConnectedForTesting());
        // bind() is call twice: once on start and then when the watchdog runs (after an unbind).
        verify(mFirstServiceConnection, times(2)).bind();
        verify(mFirstServiceConnection, times(1)).unbind();

        ShadowLooper.runUiThreadTasksIncludingDelayedTasks();
        // Watchdog should have attempted to connect again.
        verify(mFirstServiceConnection, times(3)).bind();
        verify(mFirstServiceConnection, times(2)).unbind();

        // Simulate the connection succeeding.
        mFirstServiceConnection.notifyServiceConnected(null /* iBinder */);

        ShadowLooper.runUiThreadTasksIncludingDelayedTasks();
        Assert.assertTrue(connection.isInitialBindingBound());
        Assert.assertTrue(connection.didOnServiceConnectedForTesting());
        // Watchdog should not have attempted anymore reconnection.
        verify(mFirstServiceConnection, times(3)).bind();
        verify(mFirstServiceConnection, times(2)).unbind();
    }

    @Test
    public void testWatchdogCancelledOnStop() {
        ChildProcessConnection connection = createDefaultTestConnection();
        connection.start(false /* useStrongBinding */, null /* serviceCallback */,
                true /* retryOnTimeout */);
        assertNotNull(mFirstServiceConnection);
        ShadowLooper.runUiThreadTasksIncludingDelayedTasks();
        Assert.assertTrue(connection.isInitialBindingBound());
        Assert.assertFalse(connection.didOnServiceConnectedForTesting());
        // bind() is call twice: once on start and then when the watchdog runs (after an unbind).
        verify(mFirstServiceConnection, times(2)).bind();
        verify(mFirstServiceConnection, times(1)).unbind();

        connection.stop();
        ShadowLooper.runUiThreadTasksIncludingDelayedTasks();
        Assert.assertFalse(connection.isInitialBindingBound());
        // Watchdog should not have attempted anymore reconnection.
        verify(mFirstServiceConnection, times(2)).bind();
        verify(mFirstServiceConnection, times(2)).unbind();
    }
}
