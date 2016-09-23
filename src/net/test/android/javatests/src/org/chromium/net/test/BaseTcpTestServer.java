// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.net.test;

import android.util.Log;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;

/** A base class for simple TCP test servers. */
public abstract class BaseTcpTestServer extends BaseTestServer {
    private static final String TAG = "BaseTcpTestServer";

    private ServerSocket mServerSocket;

    /**
     * Creates a TCP test server on the given port.
     *
     * @param serverPort The port to listen on for incoming TCP connections.
     * @param acceptTimeoutMs The timeout for calls to ServerSocket.accept(), in milliseconds.
     * @throws IOException If the server port can't be bound.
     */
    public BaseTcpTestServer(int serverPort, int acceptTimeoutMs) throws IOException {
        mServerSocket = new ServerSocket(serverPort);
        mServerSocket.setSoTimeout(acceptTimeoutMs);
    }

    /** Returns the port on which this server is listening for connections. */
    @Override
    public int getServerPort() {
        return mServerSocket.getLocalPort();
    }

    /** Waits for and handles an incoming request. */
    protected final void accept() {
        try {
            Socket sock = mServerSocket.accept();

            if (!validateSocket(sock)) {
                Log.e(TAG, "Socket failed validation.");
                sock.close();
                return;
            }

            handle(sock);
        } catch (SocketTimeoutException e) {
            Log.i(TAG, "Timed out waiting for incoming connection.");
        } catch (IOException e) {
            Log.e(TAG, "Error while handling incoming connection", e);
        }
    }

    /**
     * Returns whether the connection open on the given socket should be handled.
     *
     * @param sock The socket to validate.
     */
    protected abstract boolean validateSocket(Socket sock);

    /**
     * Handles the connection open on the given socket.
     *
     * @param sock The socket to handle.
     * @throws IOException If an error occurs while reading from or writing to the socket.
     */
    protected abstract void handle(Socket sock) throws IOException;
}
