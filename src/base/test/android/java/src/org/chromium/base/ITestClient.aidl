// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base;

import org.chromium.base.FileDescriptorInfo;
import org.chromium.base.MainReturnCodeResult;

/**
 * This interface is used to control child processes.
 */
interface ITestClient {
  /**
   * Runs the native <code>main</code> method in that service's process.
   * @param args the arguments passed to <code>main</code>
   * @param fdsToMap a list of file descriptors that are mapped in the native code
   * in <code>base::GlobalDescriptors</code>.
   * @return the process ID for the service's process.
   */
  int launch(in String[] args, in FileDescriptorInfo[] fdsToMap);

  /**
   * Blocks until the <code>main</code> method started with {@link #launch()} returns, or returns
   * immediately if main has already returned.
   * @param timeoutMs time in milliseconds after which this method returns even if the main method
   * has not returned yet.
   * @return a result containing whether a timeout occured and the value returned by the
   * <code>main</code> method
   */
  MainReturnCodeResult waitForMainToReturn(int timeoutMs);

  /**
   * Forces the service process to terminate and block until the process stops.
   * @param exitCode the exit code the process should terminate with.
   * @return always true, a return value is only returned to force the call to be synchronous.
   */
  boolean forceStopSynchronous(int exitCode);

  /**
   * Forces the service process to terminate.
   * @param exitCode the exit code the process should terminate with.
   */
  void forceStop(int exitCode);
}
