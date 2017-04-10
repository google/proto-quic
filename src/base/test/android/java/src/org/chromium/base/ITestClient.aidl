// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base;

import org.chromium.base.MainReturnCodeResult;
import org.chromium.base.process_launcher.FileDescriptorInfo;

/**
 * This interface is used to control child processes.
 * TODO(jcivelli): http://crbug.com/702316 remove this once ChildProcessLauncher has moved to base/.
 */
interface ITestClient {
  // On the first call to this method, the service will record the calling PID
  // and return true. Subsequent calls will only return true if the calling PID
  // is the same as the recorded one.
  boolean bindToCaller();

  /**
   * Runs the native <code>main</code> method in that service's process.
   * @param args contains the arguments passed to <code>main</code> as well as the files to be
   * mapped in the service process, see <code>org.chromium.base.ChildProcessConstants</code>.
   * @param callback a callback used to communicate back to the parent process. (until we use the
   * common launcher in base/, we'll use this test implentation and this callback is an
   * ITestCallback).
   * @return the process ID for the service's process.
   */
  int setupConnection(in Bundle args, IBinder callback);
}
