// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base;

import android.os.Handler;

import java.util.LinkedList;
import java.util.List;

/**
 * A Promise class to be used as a placeholder for a result that will be provided asynchronously.
 * It must only be accessed from a single thread.
 * @param <T> The type the Promise will be fulfilled with.
 */
public class Promise<T> {
    // TODO(peconn): Implement rejection handlers that can recover from rejection.

    // TODO(peconn): Add an IntDef here (https://crbug.com/623012).
    private static final int UNFULFILLED = 0;
    private static final int FULFILLED = 1;
    private static final int REJECTED = 2;

    private int mState = UNFULFILLED;

    private T mResult;
    private final List<Callback<T>> mFulfillCallbacks = new LinkedList<Callback<T>>();

    private Exception mRejectReason;
    private final List<Callback<Exception>> mRejectCallbacks =
            new LinkedList<Callback<Exception>>();

    private final Thread mThread;
    private final Handler mHandler;

    private boolean mThrowingRejectionHandler;

    /**
     * A function class for use when chaining Promises with {@link Promise#then(Function)}.
     */
    public interface Function<A, R> {
        R apply(A argument);
    }

    /**
     * A function class for use when chaining Promises with {@link Promise#then(AsyncFunction)}.
     */
    public interface AsyncFunction<A, R> {
        Promise<R> apply(A argument);
    }

    /**
     * An exception class for when a rejected Promise is not handled and cannot pass the rejection
     * to a subsequent Promise.
     */
    public static class UnhandledRejectionException extends RuntimeException {
        public UnhandledRejectionException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /**
     * Creates an unfulfilled promise.
     */
    public Promise() {
        mThread = Thread.currentThread();
        mHandler = new Handler();
    }

    /**
     * Convenience method that calls {@link #then(Callback, Callback)} providing a rejection
     * {@link Callback} that throws a {@link UnhandledRejectionException}. Only use this on
     * Promises that do not have rejection handlers or dependant Promises.
     */
    public void then(Callback<T> onFulfill) {
        checkThread();

        // Allow multiple single argument then(Callback)'s, but don't bother adding duplicate
        // throwing rejection handlers.
        if (mThrowingRejectionHandler) {
            thenInner(onFulfill);
            return;
        }

        assert mRejectCallbacks.size() == 0 : "Do not call the single argument "
            + "Promise.then(Callback) on a Promise that already has a rejection handler.";

        Callback<Exception> onReject = new Callback<Exception>() {
            @Override
            public void onResult(Exception reason) {
                throw new UnhandledRejectionException(
                        "Promise was rejected without a rejection handler.", reason);
            }
        };

        then(onFulfill, onReject);
        mThrowingRejectionHandler = true;
    }

    /**
     * Queues {@link Callback}s to be run when the Promise is either fulfilled or rejected. If the
     * Promise is already fulfilled or rejected, the appropriate callback will be run on the next
     * iteration of the message loop.
     *
     * @param onFulfill The Callback to be called on fulfillment.
     * @param onReject The Callback to be called on rejection. The argument to onReject will
     *         may be null if the Promise was rejected manually.
     */
    public void then(Callback<T> onFulfill, Callback<Exception> onReject) {
        checkThread();

        thenInner(onFulfill);
        exceptInner(onReject);
    }

    /**
     * Adds a rejection handler to the Promise. This handler will be called if this Promise or any
     * Promises this Promise depends on is rejected or fails. The {@link Callback} will be given
     * the exception that caused the rejection, or null if the rejection was manual (caused by a
     * call to {@link #reject()}.
     */
    public void except(Callback<Exception> onReject) {
        checkThread();

        exceptInner(onReject);
    }

    /**
     * A convenience method that returns a Callback that fulfills this Promise with its result.
     */
    public Callback<T> fulfillmentCallback() {
        return new Callback<T>() {
            @Override
            public void onResult(T result) {
                fulfill(result);
            }
        };
    }

    private void thenInner(Callback<T> onFulfill) {
        if (mState == FULFILLED) {
            postCallbackToLooper(onFulfill, mResult);
        } else if (mState == UNFULFILLED) {
            mFulfillCallbacks.add(onFulfill);
        }
    }

    private void exceptInner(Callback<Exception> onReject) {
        assert !mThrowingRejectionHandler : "Do not add an exception handler to a Promise you have "
            + "called the single argument Promise.then(Callback) on.";

        if (mState == REJECTED) {
            postCallbackToLooper(onReject, mRejectReason);
        } else if (mState == UNFULFILLED) {
            mRejectCallbacks.add(onReject);
        }
    }

    /**
     * Queues a {@link Promise.Function} to be run when the Promise is fulfilled. When this Promise
     * is fulfilled, the function will be run and its result will be place in the returned Promise.
     */
    public <R> Promise<R> then(final Function<T, R> function) {
        checkThread();

        // Create a new Promise to store the result of the function.
        final Promise<R> promise = new Promise<R>();

        // Once this Promise is fulfilled:
        // - Apply the given function to the result.
        // - Fulfill the new Promise.
        thenInner(new Callback<T>(){
            @Override
            public void onResult(T result) {
                try {
                    promise.fulfill(function.apply(result));
                } catch (Exception e) {
                    // If function application fails, reject the next Promise.
                    promise.reject(e);
                }
            }
        });

        // If this Promise is rejected, reject the next Promise.
        exceptInner(rejectPromiseCallback(promise));

        return promise;
    }

    /**
     * Queues a {@link Promise.AsyncFunction} to be run when the Promise is fulfilled. When this
     * Promise is fulfilled, the AsyncFunction will be run. When the result of the AsyncFunction is
     * available, it will be placed in the returned Promise.
     */
    public <R> Promise<R> then(final AsyncFunction<T, R> function) {
        checkThread();

        // Create a new Promise to be returned.
        final Promise<R> promise = new Promise<R>();

        // Once this Promise is fulfilled:
        // - Apply the given function to the result (giving us an inner Promise).
        // - On fulfillment of this inner Promise, fulfill our return Promise.
        thenInner(new Callback<T>() {
            @Override
            public void onResult(T result) {
                try {
                    // When the inner Promise is fulfilled, fulfill the return Promise.
                    // Alternatively, if the inner Promise is rejected, reject the return Promise.
                    function.apply(result).then(new Callback<R>() {
                        @Override
                        public void onResult(R result) {
                            promise.fulfill(result);
                        }
                    }, rejectPromiseCallback(promise));
                } catch (Exception e) {
                    // If creating the inner Promise failed, reject the next Promise.
                    promise.reject(e);
                }

            }
        });

        // If this Promise is rejected, reject the next Promise.
        exceptInner(rejectPromiseCallback(promise));

        return promise;
    }

    /**
     * Fulfills the Promise with the result and passes it to any {@link Callback}s previously queued
     * on the next iteration of the message loop.
     */
    public void fulfill(final T result) {
        checkThread();
        assert mState == UNFULFILLED;

        mState = FULFILLED;
        mResult = result;

        for (final Callback<T> callback : mFulfillCallbacks) {
            postCallbackToLooper(callback, result);
        }

        mFulfillCallbacks.clear();
    }

    /**
     * Rejects the Promise, rejecting all those Promises that rely on it.
     *
     * This may throw an exception if a dependent Promise fails to handle the rejection, so it is
     * important to make it explicit when a Promise may be rejected, so that users of that Promise
     * know to provide rejection handling.
     */
    public void reject(final Exception reason) {
        checkThread();
        assert mState == UNFULFILLED;

        mState = REJECTED;
        mRejectReason = reason;

        for (final Callback<Exception> callback : mRejectCallbacks) {
            postCallbackToLooper(callback, reason);
        }
        mRejectCallbacks.clear();
    }

    /**
     * Rejects a Promise, see {@link #reject(Exception)}.
     */
    public void reject() {
        reject(null);
    }

    /**
     * Returns whether the promise is fulfilled.
     */
    public boolean isFulfilled() {
        checkThread();

        return mState == FULFILLED;
    }

    /**
     * Returns whether the promise is rejected.
     */
    public boolean isRejected() {
        checkThread();

        return mState == REJECTED;
    }

    /**
     * Convenience method to return a Promise fulfilled with the given result.
     */
    public static <T> Promise<T> fulfilled(T result) {
        Promise<T> promise = new Promise<T>();
        promise.fulfill(result);
        return promise;
    }

    private void checkThread() {
        assert mThread == Thread.currentThread() : "Promise must only be used on a single Thread.";
    }

    // We use a different template parameter here so this can be used for both T and Throwables.
    private <S> void postCallbackToLooper(final Callback<S> callback, final S result) {
        // Post the callbacks to the Thread looper so we don't get a long chain of callbacks
        // holding up the thread.
        mHandler.post(new Runnable() {
            @Override
            public void run() {
                callback.onResult(result);
            }
        });
    }

    /**
     * Convenience method to construct a callback that rejects the given Promise.
     */
    private static <T> Callback<Exception> rejectPromiseCallback(final Promise<T> promise) {
        return new Callback<Exception>() {
            @Override
            public void onResult(Exception reason) {
                promise.reject(reason);
            }
        };
    }
}