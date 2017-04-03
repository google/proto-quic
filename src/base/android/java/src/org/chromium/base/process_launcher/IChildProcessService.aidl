// Copyright 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base.process_launcher;

import android.os.Bundle;

interface IChildProcessService {
  // On the first call to this method, the service will record the calling PID
  // and return true. Subsequent calls will only return true if the calling PID
  // is the same as the recorded one.
  boolean bindToCaller();

  // Sets up the initial IPC channel and returns the pid of the child process.
  int setupConnection(in Bundle args, IBinder callback);

  // Asks the child service to crash so that we can test the termination logic.
  void crashIntentionallyForTesting();
}
