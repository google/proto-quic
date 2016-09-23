// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.net.test;

import android.util.Log;

import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpStatus;
import org.apache.http.HttpVersion;
import org.apache.http.RequestLine;
import org.apache.http.entity.StringEntity;
import org.apache.http.message.BasicHttpResponse;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.Socket;

/**
 * A server that spawns test servers based on request JSONs.
 *
 * This communicates with net::SpawnerCommunicator according to the protocol specified in
 * //net/test/spawned_test_server/spawner_communicator.h. It spawns test servers on the device.
 */
public class TestServerSpawner extends BaseHttpTestServer {
    private static final String TAG = "TestServerSpawner";

    private static final int ARBITRARY_MAX_JSON_SIZE = 65536;
    private static final String COMMAND_KILL = "/kill";
    private static final String COMMAND_PING = "/ping";
    private static final String COMMAND_START = "/start";

    private BaseTestServer mTestServer;
    private Thread mTestServerThread;

    /**
     * Creates a test server spawner on the given port.
     *
     * @param serverPort The port to listen on for incoming connections.
     * @param acceptTimeoutMs The timeout for calls to ServerSocket.accept(), in milliseconds.
     * @throws IOException If the server port can't be bound.
     */
    public TestServerSpawner(int serverPort, int acceptTimeoutMs) throws IOException {
        super(serverPort, acceptTimeoutMs);
        mTestServer = null;
        mTestServerThread = null;
    }

    /**
     * Returns true if the socket is coming from a local address.
     *
     * @param sock The socket to validate.
     * @return True if the remote endpoint is local, false otherwise.
     */
    @Override
    protected boolean validateSocket(Socket sock) {
        return sock.getInetAddress().isLoopbackAddress();
    }

    /**
     * Handles a GET request.
     *
     * This handles the /kill and /ping commands. It returns 403s for anything else.
     *
     * @param request The GET request to handle.
     * @param callback The callback to give the response to |request|.
     */
    @Override
    protected void handleGet(HttpRequest request, HttpResponseCallback callback) {
        RequestLine requestLine = request.getRequestLine();
        String uri = requestLine.getUri();

        int status = HttpStatus.SC_INTERNAL_SERVER_ERROR;
        String reason = "";
        HttpEntity entity = null;

        try {
            // TODO(jbudorick): Refactor how this communicates with RemoteTestServer and
            // SpawnerCommunicator (or maybe how we spawn and manage test servers on android
            // entirely) once tests are no longer using chrome_test_server_spawner.py.
            // The server startup and shutdown processes should be done in code (e.g. with events)
            // rather than over HTTP. crbug/452596
            if (COMMAND_KILL.equals(uri)) {
                Log.i(TAG, "Received GET /kill request.");

                if (mTestServer != null) {
                    mTestServer.stop();
                    mTestServerThread.join();
                    status = HttpStatus.SC_OK;
                    entity = new StringEntity("killed");
                    mTestServer = null;
                } else {
                    status = HttpStatus.SC_BAD_REQUEST;
                    reason = "Test server does not exist.";
                }
            } else if (COMMAND_PING.equals(uri)) {
                Log.i(TAG, "Received GET /ping request.");
                status = HttpStatus.SC_OK;
                entity = new StringEntity("ready");
            } else {
                status = HttpStatus.SC_FORBIDDEN;
            }
        } catch (InterruptedException e) {
            Log.e(TAG, "Interrupted while joining test server thread: " + e.toString());
        } catch (UnsupportedEncodingException e) {
            Log.e(TAG, "Unsupported encoding while writing response entity: " + e.toString());
            entity = null;
        }

        BasicHttpResponse response = new BasicHttpResponse(HttpVersion.HTTP_1_0, status, reason);
        response.setEntity(entity);
        callback.onResponse(response);
    }

    /**
     * Handles a POST request.
     *
     * This handles the /start command. It returns 403s for anything else.
     *
     * @param request The POST request to handle.
     * @param callback The callback to give the response to |request|.
     */
    @Override
    protected void handlePost(HttpEntityEnclosingRequest request, HttpResponseCallback callback)
            throws HttpException {
        RequestLine requestLine = request.getRequestLine();
        String uri = requestLine.getUri();

        int status = HttpStatus.SC_INTERNAL_SERVER_ERROR;
        String reason = "";
        HttpEntity responseEntity = null;

        if (COMMAND_START.equals(uri)) {
            Log.i(TAG, "Received POST /start request.");
            BufferedReader entityReader = null;
            try {
                HttpEntity requestEntity = request.getEntity();
                if (requestEntity.getContentLength() > ARBITRARY_MAX_JSON_SIZE) {
                    throw new HttpException("Request JSON too long ("
                            + Long.toString(requestEntity.getContentLength()) + " bytes)");
                }

                entityReader = new BufferedReader(
                        new InputStreamReader(new BufferedInputStream(requestEntity.getContent())));
                StringBuilder rawJson = new StringBuilder();
                for (String line = entityReader.readLine(); line != null;
                        line = entityReader.readLine()) {
                    rawJson.append(line);
                }

                mTestServer = new TestServerBuilder(new JSONObject(rawJson.toString())).build();
                mTestServerThread = new Thread(mTestServer);
                mTestServerThread.start();

                status = HttpStatus.SC_OK;
                JSONObject entityJson = new JSONObject();
                entityJson.put("port", mTestServer.getServerPort());
                entityJson.put("message", "started");
                responseEntity = new StringEntity(entityJson.toString());
            } catch (UnsupportedOperationException e) {
                // TODO(jbudorick): Remove this catch block once TestServerFactory.createTestServer
                // is fully implemented.
                throw new HttpException("Error creating test server", e);
            } catch (JSONException e) {
                throw new HttpException("Error handling JSON", e);
            } catch (UnsupportedEncodingException e) {
                throw new HttpException("Error generating response", e);
            } catch (IOException e) {
                throw new HttpException("Error while reading HTTP entity", e);
            } finally {
                try {
                    if (entityReader != null) entityReader.close();
                } catch (IOException e) {
                    Log.e(TAG, "Unable to close entity input stream", e);
                }
            }
        } else {
            status = HttpStatus.SC_FORBIDDEN;
        }

        BasicHttpResponse response = new BasicHttpResponse(HttpVersion.HTTP_1_0, status, reason);
        response.setEntity(responseEntity);
        callback.onResponse(response);
    }
}
