// Copyright 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base.test.util;

import static org.chromium.base.test.util.ScalableTimeout.scaleTimeout;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * A helper class that encapsulates listening and blocking for callbacks.
 *
 * Sample usage:
 *
 * // Let us assume that this interface is defined by some piece of production code and is used
 * // to communicate events that occur in that piece of code. Let us further assume that the
 * // production code runs on the main thread test code runs on a separate test thread.
 * // An instance that implements this interface would be injected by test code to ensure that the
 * // methods are being called on another thread.
 * interface Delegate {
 *     void onOperationFailed(String errorMessage);
 *     void onDataPersisted();
 * }
 *
 * // This is the inner class you'd write in your test case to later inject into the production
 * // code.
 * class TestDelegate implements Delegate {
 *     // This is the preferred way to create a helper that stores the parameters it receives
 *     // when called by production code.
 *     public static class OnOperationFailedHelper extends CallbackHelper {
 *         private String mErrorMessage;
 *
 *         public void getErrorMessage() {
 *             assert getCallCount() > 0;
 *             return mErrorMessage;
 *         }
 *
 *         public void notifyCalled(String errorMessage) {
 *             mErrorMessage = errorMessage;
 *             // It's important to call this after all parameter assignments.
 *             notifyCalled();
 *         }
 *     }
 *
 *     // There should be one CallbackHelper instance per method.
 *     private OnOperationFailedHelper mOnOperationFailedHelper;
 *     private CallbackHelper mOnDataPersistedHelper;
 *
 *     public OnOperationFailedHelper getOnOperationFailedHelper() {
 *         return mOnOperationFailedHelper;
 *     }
 *
 *     public CallbackHelper getOnDataPersistedHelper() {
 *         return mOnDataPersistedHelper;
 *     }
 *
 *     @Override
 *     public void onOperationFailed(String errorMessage) {
 *         mOnOperationFailedHelper.notifyCalled(errorMessage);
 *     }
 *
 *     @Override
 *     public void onDataPersisted() {
 *         mOnDataPersistedHelper.notifyCalled();
 *     }
 * }
 *
 * // This is a sample test case.
 * public void testCase() throws Exception {
 *     // Create the TestDelegate to inject into production code.
 *     TestDelegate delegate = new TestDelegate();
 *     // Create the production class instance that is being tested and inject the test delegate.
 *     CodeUnderTest codeUnderTest = new CodeUnderTest();
 *     codeUnderTest.setDelegate(delegate);
 *
 *     // Typically you'd get the current call count before performing the operation you expect to
 *     // trigger the callback. There can't be any callbacks 'in flight' at this moment, otherwise
 *     // the call count is unpredictable and the test will be flaky.
 *     int onOperationFailedCallCount = delegate.getOnOperationFailedHelper().getCallCount();
 *     codeUnderTest.doSomethingThatEndsUpCallingOnOperationFailedFromAnotherThread();
 *     // It's safe to do other stuff here, if needed.
 *     ....
 *     // Wait for the callback if it hadn't been called yet, otherwise return immediately. This
 *     // can throw an exception if the callback doesn't arrive within the timeout.
 *     delegate.getOnOperationFailedHelper().waitForCallback(onOperationFailedCallCount);
 *     // Access to method parameters is now safe.
 *     assertEquals("server error", delegate.getOnOperationFailedHelper().getErrorMessage());
 *
 *     // Being able to pass the helper around lets us build methods which encapsulate commonly
 *     // performed tasks.
 *     doSomeOperationAndWait(codeUnerTest, delegate.getOnOperationFailedHelper());
 *
 *     // The helper can be reused for as many calls as needed, just be sure to get the count each
 *     // time.
 *     onOperationFailedCallCount = delegate.getOnOperationFailedHelper().getCallCount();
 *     codeUnderTest.doSomethingElseButStillFailOnAnotherThread();
 *     delegate.getOnOperationFailedHelper().waitForCallback(onOperationFailedCallCount);
 *
 *     // It is also possible to use more than one helper at a time.
 *     onOperationFailedCallCount = delegate.getOnOperationFailedHelper().getCallCount();
 *     int onDataPersistedCallCount = delegate.getOnDataPersistedHelper().getCallCount();
 *     codeUnderTest.doSomethingThatPersistsDataButFailsInSomeOtherWayOnAnotherThread();
 *     delegate.getOnDataPersistedHelper().waitForCallback(onDataPersistedCallCount);
 *     delegate.getOnOperationFailedHelper().waitForCallback(onOperationFailedCallCount);
 * }
 *
 * // Shows how to turn an async operation + completion callback into a synchronous operation.
 * private void doSomeOperationAndWait(final CodeUnderTest underTest,
 *         CallbackHelper operationHelper) throws InterruptedException, TimeoutException {
 *     final int callCount = operationHelper.getCallCount();
 *     getInstrumentation().runOnMainSync(new Runnable() {
 *         @Override
 *         public void run() {
 *             // This schedules a call to a method on the injected TestDelegate. The TestDelegate
 *             // implementation will then call operationHelper.notifyCalled().
 *             underTest.operation();
 *         }
 *      });
 *      operationHelper.waitForCallback(callCount);
 * }
 *
 */
public class CallbackHelper {
    /** The default timeout (in seconds) for a callback to wait. */
    public static final long WAIT_TIMEOUT_SECONDS = scaleTimeout(5);

    private final Object mLock = new Object();
    private int mCallCount;

    /**
     * Gets the number of times the callback has been called.
     *
     * The call count can be used with the waitForCallback() method, indicating a point
     * in time after which the caller wishes to record calls to the callback.
     *
     * In order to wait for a callback caused by X, the call count should be obtained
     * before X occurs.
     *
     * NOTE: any call to the callback that occurs after the call count is obtained
     * will result in the corresponding wait call to resume execution. The call count
     * is intended to 'catch' callbacks that occur after X but before waitForCallback()
     * is called.
     */
    public int getCallCount() {
        synchronized (mLock) {
            return mCallCount;
        }
    }

    /**
     * Blocks until the callback is called the specified number of
     * times or throws an exception if we exceeded the specified time frame.
     *
     * This will wait for a callback to be called a specified number of times after
     * the point in time at which the call count was obtained.  The method will return
     * immediately if a call occurred the specified number of times after the
     * call count was obtained but before the method was called, otherwise the method will
     * block until the specified call count is reached.
     *
     * @param msg The error message to use if the callback times out.
     * @param currentCallCount the value obtained by calling getCallCount().
     * @param numberOfCallsToWaitFor number of calls (counting since
     *                               currentCallCount was obtained) that we will wait for.
     * @param timeout timeout value. We will wait the specified amount of time for a single
     *                callback to occur so the method call may block up to
     *                <code>numberOfCallsToWaitFor * timeout</code> units.
     * @param unit timeout unit.
     * @throws InterruptedException
     * @throws TimeoutException Thrown if the method times out before onPageFinished is called.
     */
    public void waitForCallback(String msg, int currentCallCount, int numberOfCallsToWaitFor,
            long timeout, TimeUnit unit) throws InterruptedException, TimeoutException {
        assert mCallCount >= currentCallCount;
        assert numberOfCallsToWaitFor > 0;
        synchronized (mLock) {
            int callCountWhenDoneWaiting = currentCallCount + numberOfCallsToWaitFor;
            while (callCountWhenDoneWaiting > mCallCount) {
                int callCountBeforeWait = mCallCount;
                mLock.wait(unit.toMillis(timeout));
                if (callCountBeforeWait == mCallCount) {
                    throw new TimeoutException(msg == null ? "waitForCallback timed out!" : msg);
                }
            }
        }
    }

    /**
     * @see #waitForCallback(String, int, int, long, TimeUnit)
     */
    public void waitForCallback(int currentCallCount, int numberOfCallsToWaitFor, long timeout,
            TimeUnit unit) throws InterruptedException, TimeoutException {
        waitForCallback(null, currentCallCount, numberOfCallsToWaitFor, timeout, unit);
    }

    /**
     * @see #waitForCallback(String, int, int, long, TimeUnit)
     */
    public void waitForCallback(int currentCallCount, int numberOfCallsToWaitFor)
            throws InterruptedException, TimeoutException {
        waitForCallback(null, currentCallCount, numberOfCallsToWaitFor,
                WAIT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }

    /**
     * @see #waitForCallback(String, int, int, long, TimeUnit)
     */
    public void waitForCallback(String msg, int currentCallCount)
            throws InterruptedException, TimeoutException {
        waitForCallback(msg, currentCallCount, 1, WAIT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }

    /**
     * @see #waitForCallback(String, int, int, long, TimeUnit)
     */
    public void waitForCallback(int currentCallCount)
            throws InterruptedException, TimeoutException {
        waitForCallback(null, currentCallCount, 1, WAIT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }

    /**
     * Should be called when the callback associated with this helper object is called.
     */
    public void notifyCalled() {
        synchronized (mLock) {
            mCallCount++;
            mLock.notifyAll();
        }
    }
}
