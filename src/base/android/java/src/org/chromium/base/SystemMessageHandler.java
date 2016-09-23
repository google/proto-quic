// Copyright 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base;

import android.annotation.SuppressLint;
import android.os.Build;
import android.os.Handler;
import android.os.Message;

import org.chromium.base.annotations.CalledByNative;
import org.chromium.base.annotations.MainDex;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

@MainDex
class SystemMessageHandler extends Handler {

    private static final String TAG = "cr.SysMessageHandler";

    private static final int SCHEDULED_WORK = 1;
    private static final int DELAYED_SCHEDULED_WORK = 2;

    // Native class pointer set by the constructor of the SharedClient native class.
    private long mMessagePumpDelegateNative = 0;
    private long mMessagePumpNative = 0;
    private long mDelayedScheduledTimeTicks = 0;

    protected SystemMessageHandler(long messagePumpDelegateNative, long messagePumpNative) {
        mMessagePumpDelegateNative = messagePumpDelegateNative;
        mMessagePumpNative = messagePumpNative;
    }

    @Override
    public void handleMessage(Message msg) {
        if (msg.what == DELAYED_SCHEDULED_WORK) {
            mDelayedScheduledTimeTicks = 0;
        }
        nativeDoRunLoopOnce(
                mMessagePumpDelegateNative, mMessagePumpNative, mDelayedScheduledTimeTicks);
    }

    @SuppressWarnings("unused")
    @CalledByNative
    private void scheduleWork() {
        sendMessage(obtainAsyncMessage(SCHEDULED_WORK));
    }

    @SuppressWarnings("unused")
    @CalledByNative
    private void scheduleDelayedWork(long delayedTimeTicks, long millis) {
        if (mDelayedScheduledTimeTicks != 0) {
            removeMessages(DELAYED_SCHEDULED_WORK);
        }
        mDelayedScheduledTimeTicks = delayedTimeTicks;
        sendMessageDelayed(obtainAsyncMessage(DELAYED_SCHEDULED_WORK), millis);
    }

    @SuppressWarnings("unused")
    @CalledByNative
    private void removeAllPendingMessages() {
        removeMessages(SCHEDULED_WORK);
        removeMessages(DELAYED_SCHEDULED_WORK);
    }

    private Message obtainAsyncMessage(int what) {
        // Marking the message async provides fair Chromium task dispatch when
        // served by the Android UI thread's Looper, avoiding stalls when the
        // Looper has a sync barrier.
        Message msg = Message.obtain();
        msg.what = what;
        MessageCompat.setAsynchronous(msg, true);
        return msg;
    }

    /**
     * Abstraction utility class for marking a Message as asynchronous. Prior
     * to L MR1 the async Message API was hidden, and for such cases we fall
     * back to using reflection to obtain the necessary method.
     */
    private static class MessageCompat {
        /**
         * @See android.os.Message#setAsynchronous(boolean)
         */
        public static void setAsynchronous(Message message, boolean async) {
            IMPL.setAsynchronous(message, async);
        }

        interface MessageWrapperImpl {
            /**
             * @See android.os.Message#setAsynchronous(boolean)
             */
            public void setAsynchronous(Message message, boolean async);
        }

        static final MessageWrapperImpl IMPL;
        static {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
                IMPL = new LollipopMr1MessageWrapperImpl();
            } else {
                IMPL = new LegacyMessageWrapperImpl();
            }
        }

        static class LollipopMr1MessageWrapperImpl implements MessageWrapperImpl {
            @SuppressLint("NewApi")
            @Override
            public void setAsynchronous(Message msg, boolean async) {
                msg.setAsynchronous(async);
            }
        }

        static class LegacyMessageWrapperImpl implements MessageWrapperImpl {
            // Reflected API for marking a message as asynchronous.
            // Note: Use of this API is experimental and likely to evolve in the future.
            private Method mMessageMethodSetAsynchronous;

            LegacyMessageWrapperImpl() {
                try {
                    Class<?> messageClass = Class.forName("android.os.Message");
                    mMessageMethodSetAsynchronous =
                            messageClass.getMethod("setAsynchronous", new Class[] {boolean.class});
                } catch (ClassNotFoundException e) {
                    Log.e(TAG, "Failed to find android.os.Message class", e);
                } catch (NoSuchMethodException e) {
                    Log.e(TAG, "Failed to load Message.setAsynchronous method", e);
                } catch (RuntimeException e) {
                    Log.e(TAG, "Exception while loading Message.setAsynchronous method", e);
                }
            }

            @Override
            public void setAsynchronous(Message msg, boolean async) {
                if (mMessageMethodSetAsynchronous == null) return;
                // If invocation fails, assume this is indicative of future
                // failures, and avoid log spam by nulling the reflected method.
                try {
                    mMessageMethodSetAsynchronous.invoke(msg, async);
                } catch (IllegalAccessException e) {
                    Log.e(TAG, "Illegal access to async message creation, disabling.");
                    mMessageMethodSetAsynchronous = null;
                } catch (IllegalArgumentException e) {
                    Log.e(TAG, "Illegal argument for async message creation, disabling.");
                    mMessageMethodSetAsynchronous = null;
                } catch (InvocationTargetException e) {
                    Log.e(TAG, "Invocation exception during async message creation, disabling.");
                    mMessageMethodSetAsynchronous = null;
                } catch (RuntimeException e) {
                    Log.e(TAG, "Runtime exception during async message creation, disabling.");
                    mMessageMethodSetAsynchronous = null;
                }
            }
        }
    }

    @CalledByNative
    private static SystemMessageHandler create(
            long messagePumpDelegateNative, long messagePumpNative) {
        return new SystemMessageHandler(messagePumpDelegateNative, messagePumpNative);
    }

    private native void nativeDoRunLoopOnce(
            long messagePumpDelegateNative, long messagePumpNative, long delayedScheduledTimeTicks);
}
