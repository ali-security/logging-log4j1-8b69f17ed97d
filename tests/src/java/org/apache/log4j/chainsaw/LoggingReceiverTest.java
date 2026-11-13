/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.log4j.chainsaw;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Set;
import java.util.Vector;

import junit.framework.TestCase;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.spi.LoggingEvent;

/**
 * Checks that the Chainsaw {@link LoggingReceiver} is not exposed to
 * CVE-2023-26464: a logging event carrying deeply nested hash based
 * collections must be refused instead of keeping the receiver busy in an
 * exponential hashCode() computation.
 */
public class LoggingReceiverTest extends TestCase {

    /**
     * How long the client waits for the receiver to close the connection. A
     * protected receiver does so almost immediately, an unprotected one never.
     */
    private static final int TIMEOUT_MS = 20000;

    /**
     * More logging events, each with its own MDC Hashtable, than the
     * collection budget of a single deserialized object graph.
     */
    private static final int MANY_EVENTS = 40;

    private RecordingModel model;
    private ServerSocket serverSocket;

    public LoggingReceiverTest(final String testName) {
        super(testName);
    }

    protected void setUp() throws Exception {
        model = new RecordingModel();
        LoggingReceiver receiver = new LoggingReceiver(model, 0);
        Field socketField = LoggingReceiver.class.getDeclaredField("mSvrSock");
        socketField.setAccessible(true);
        serverSocket = (ServerSocket) socketField.get(receiver);
        receiver.start();
    }

    protected void tearDown() throws Exception {
        serverSocket.close();
    }

    /**
     * CVE-2023-26464 exploit: the MDC of a logging event holds deeply nested
     * HashSets. The receiver must drop the connection without adding the
     * event, nor any event sent after it.
     */
    public void testNestedCollectionsAreRejected() throws Exception {
        Hashtable mdc = new Hashtable();
        mdc.put("payload", nestedHashSets(100));

        Socket client = connect();
        try {
            ObjectOutputStream oos = new ObjectOutputStream(client.getOutputStream());
            oos.writeObject(makeEvent("before", null));
            oos.writeObject(makeEvent("payload", mdc));
            oos.writeObject(makeEvent("after", null));
            oos.flush();

            waitForReceiverToClose(client);
        } finally {
            client.close();
        }

        assertEquals(1, model.events.size());
        assertEquals("before", ((EventDetails) model.events.elementAt(0)).getMessage());
    }

    /**
     * Legitimate events keep flowing on a long lived connection: the
     * collection budget applies to each event, not to the whole connection.
     */
    public void testManyEventsWithMDCAreAccepted() throws Exception {
        Socket client = connect();
        try {
            ObjectOutputStream oos = new ObjectOutputStream(client.getOutputStream());
            for (int i = 0; i < MANY_EVENTS; i++) {
                Hashtable mdc = new Hashtable();
                mdc.put("index", String.valueOf(i));
                oos.writeObject(makeEvent("event " + i, mdc));
            }
            oos.flush();
            client.shutdownOutput();

            waitForReceiverToClose(client);
        } finally {
            client.close();
        }

        assertEquals(MANY_EVENTS, model.events.size());
        assertEquals("event " + (MANY_EVENTS - 1),
                ((EventDetails) model.events.elementAt(MANY_EVENTS - 1)).getMessage());
    }

    private Socket connect() throws IOException {
        Socket client = new Socket(InetAddress.getByName("127.0.0.1"), serverSocket.getLocalPort());
        client.setSoTimeout(TIMEOUT_MS);
        return client;
    }

    /**
     * Blocks until the receiver closed its side of the connection, which it
     * does once it stopped reading events.
     */
    private static void waitForReceiverToClose(final Socket client) throws IOException {
        try {
            assertEquals(-1, client.getInputStream().read());
        } catch (InterruptedIOException e) {
            fail("LoggingReceiver still reading the connection after " + TIMEOUT_MS + " ms");
        } catch (SocketException e) {
            // connection reset: the receiver closed with unread bytes left
        }
    }

    private static LoggingEvent makeEvent(final String message, final Hashtable mdc) {
        Logger logger = Logger.getLogger("org.apache.log4j.chainsaw.LoggingReceiverTest");
        return new LoggingEvent(Logger.class.getName(), logger, System.currentTimeMillis(), Level.INFO,
                message, "main", null, null, null, mdc);
    }

    /**
     * Deeply nested HashSets forming a DAG: deserializing them computes
     * about 2^depth hashCode() calls unless the stream refuses them first.
     */
    private static Set nestedHashSets(final int depth) {
        Set root = new HashSet();
        Set s1 = root;
        Set s2 = new HashSet();
        for (int i = 0; i < depth; i++) {
            Set t1 = new HashSet();
            Set t2 = new HashSet();
            t1.add("foo");
            s1.add(t1);
            s1.add(t2);
            s2.add(t1);
            s2.add(t2);
            s1 = t1;
            s2 = t2;
        }
        return root;
    }

    /**
     * Table model recording the events the receiver hands over.
     */
    private static class RecordingModel extends MyTableModel {
        final Vector events = new Vector();

        public void addEvent(final EventDetails aEvent) {
            events.addElement(aEvent);
        }
    }
}
