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
package org.apache.log4j.net;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InvalidObjectException;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Set;

import junit.framework.TestCase;

import org.apache.log4j.Hierarchy;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.VectorAppender;
import org.apache.log4j.spi.LoggingEvent;
import org.apache.log4j.spi.RootLogger;

/**
 * Tests for {@link HardenedObjectInputStream} collection count limiting
 * that mitigates CVE-2023-26464.
 *
 * CVE-2023-26464: Deeply nested hash-based collection structures cause
 * exponential hashCode() computation during deserialization, leading
 * to Denial of Service. The fix limits the total number of Map/Collection
 * instances that can be deserialized in a single object graph.
 */
public class HardenedObjectInputStreamTest extends TestCase {

    /**
     * How long an exploit test waits for deserialization to give up. A
     * protected stream rejects the payloads below almost immediately, an
     * unprotected one never finishes.
     */
    private static final long TIMEOUT_MS = 20000;

    /** Nesting depth of the attack payloads, i.e. about 2^100 hashCode() calls. */
    private static final int ATTACK_DEPTH = 100;

    private byte[] serialize(Object obj) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(obj);
        oos.close();
        return bos.toByteArray();
    }

    /**
     * CVE-2023-26464: The exact attack payload from the logback advisory.
     * Deeply nested HashSet structures that cause exponential hashCode()
     * computation. The collection count limit must reject this before
     * the computation becomes dangerous.
     */
    public void testDeeplyNestedHashSetRejected() throws Exception {
        // Build the CVE-2023-26464 attack payload: deeply nested HashSets
        // that form a DAG causing O(2^N) hashCode() computation
        Set root = new HashSet();
        Set s1 = root;
        Set s2 = new HashSet();
        for (int i = 0; i < 100; i++) {
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
        byte[] serialized = serialize(root);

        ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
        String[] whitelist = new String[0];
        HardenedObjectInputStream hois = new HardenedObjectInputStream(bis, whitelist);

        try {
            hois.readObject();
            fail("Deeply nested HashSet should be rejected due to collection count limit");
        } catch (InvalidObjectException e) {
            // Our resolveObject-based collection count limit caught it (pre-JDK 9)
            assertTrue("Should mention collection limit",
                    e.getMessage().indexOf("collection") >= 0);
        } catch (java.io.InvalidClassException e) {
            // On JDK 9+, the built-in ObjectInputFilter may reject it first
            // with "filter status: REJECTED". Either way, the attack is blocked.
        } finally {
            hois.close();
        }
    }

    /**
     * A moderate number of nested collections (within the limit) should
     * still be allowed. This tests that normal LoggingEvent-like payloads
     * with a few Hashtables work fine.
     */
    public void testModerateCollectionsAllowed() throws Exception {
        // Simulate a LoggingEvent with MDC (Hashtable) containing a few entries
        Hashtable mdc = new Hashtable();
        mdc.put("user", "alice");
        mdc.put("session", "abc123");
        mdc.put("requestId", "req-456");
        byte[] serialized = serialize(mdc);

        ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
        String[] whitelist = new String[0];
        HardenedObjectInputStream hois = new HardenedObjectInputStream(bis, whitelist);

        Object result = hois.readObject();
        assertTrue(result instanceof Hashtable);
        assertEquals("alice", ((Hashtable) result).get("user"));
        hois.close();
    }

    /**
     * Simple non-collection objects should work unaffected.
     */
    public void testStringAllowed() throws Exception {
        byte[] serialized = serialize("hello world");

        ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
        String[] whitelist = new String[0];
        HardenedObjectInputStream hois = new HardenedObjectInputStream(bis, whitelist);

        assertEquals("hello world", hois.readObject());
        hois.close();
    }

    /**
     * CVE-2023-26464 with the "deeply nested hashtable" named by the
     * advisory instead of HashSets.
     */
    public void testDeeplyNestedHashtableRejected() throws Exception {
        HardenedObjectInputStream hois = new HardenedObjectInputStream(
                new ByteArrayInputStream(serialize(nestedHashtables(ATTACK_DEPTH))), new String[0]);
        try {
            assertCollectionLimitHit(readAdaptedInBackground(hois));
        } finally {
            hois.close();
        }
    }

    /**
     * The attack as received by SocketNode and Chainsaw: the nested sets
     * travel inside the MDC of an otherwise legitimate logging event.
     */
    public void testNestedCollectionsInLoggingEventRejected() throws Exception {
        Hashtable mdc = new Hashtable();
        mdc.put("payload", nestedHashSets(ATTACK_DEPTH));
        HardenedObjectInputStream hois = new HardenedLoggingEventInputStream(
                new ByteArrayInputStream(serialize(makeEvent("payload", mdc))));
        try {
            assertCollectionLimitHit(readAdaptedInBackground(hois));
        } finally {
            hois.close();
        }
    }

    /**
     * Exactly {@link HardenedObjectInputStream#MAX_COLLECTION_COUNT}
     * collections are accepted, one more is refused.
     */
    public void testCollectionCountLimit() throws Exception {
        List atLimit = listOfLists(HardenedObjectInputStream.MAX_COLLECTION_COUNT - 1);
        HardenedObjectInputStream hois = new HardenedObjectInputStream(
                new ByteArrayInputStream(serialize(atLimit)), new String[0]);
        try {
            assertEquals(atLimit, hois.readAdaptedObject());
        } finally {
            hois.close();
        }

        List overLimit = listOfLists(HardenedObjectInputStream.MAX_COLLECTION_COUNT);
        hois = new HardenedObjectInputStream(
                new ByteArrayInputStream(serialize(overLimit)), new String[0]);
        try {
            hois.readAdaptedObject();
            fail("More than MAX_COLLECTION_COUNT collections should be rejected");
        } catch (InvalidObjectException e) {
            assertCollectionLimitHit(e);
        } finally {
            hois.close();
        }
    }

    /**
     * Every top-level object read through readAdaptedObject() gets its own
     * collection budget, so a long lived stream keeps accepting events.
     */
    public void testReadAdaptedObjectResetsCollectionBudget() throws Exception {
        int count = HardenedObjectInputStream.MAX_COLLECTION_COUNT + 8;
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        for (int i = 0; i < count; i++) {
            Hashtable mdc = new Hashtable();
            mdc.put("index", String.valueOf(i));
            oos.writeObject(mdc);
        }
        oos.close();

        HardenedObjectInputStream hois = new HardenedObjectInputStream(
                new ByteArrayInputStream(bos.toByteArray()), new String[0]);
        try {
            for (int i = 0; i < count; i++) {
                Hashtable mdc = (Hashtable) hois.readAdaptedObject();
                assertEquals(String.valueOf(i), mdc.get("index"));
            }
        } finally {
            hois.close();
        }
    }

    /**
     * SocketNode (used by SocketServer and SimpleSocketServer) keeps logging
     * events from a client after more than MAX_COLLECTION_COUNT events, each
     * carrying an MDC Hashtable, went through the same connection.
     */
    public void testSocketNodeAcceptsManyEventsWithMDC() throws Exception {
        int count = HardenedObjectInputStream.MAX_COLLECTION_COUNT + 8;
        Object[] events = new Object[count];
        for (int i = 0; i < count; i++) {
            Hashtable mdc = new Hashtable();
            mdc.put("index", String.valueOf(i));
            events[i] = makeEvent("event " + i, mdc);
        }

        VectorAppender appender = runSocketNode(events);

        assertEquals(count, appender.getVector().size());
        LoggingEvent last = (LoggingEvent) appender.getVector().elementAt(count - 1);
        assertEquals("event " + (count - 1), last.getRenderedMessage());
        assertEquals(String.valueOf(count - 1), last.getMDC("index"));
    }

    /**
     * End to end CVE-2023-26464 exploit against SocketNode: a remote client
     * sends a logging event whose MDC holds deeply nested HashSets. The node
     * must drop the connection instead of spinning in hashCode().
     */
    public void testSocketNodeRejectsNestedCollections() throws Exception {
        Hashtable mdc = new Hashtable();
        mdc.put("payload", nestedHashSets(ATTACK_DEPTH));

        VectorAppender appender = runSocketNode(new Object[] {
                makeEvent("before", null), makeEvent("payload", mdc), makeEvent("after", null) });

        assertEquals(1, appender.getVector().size());
        assertEquals("before", ((LoggingEvent) appender.getVector().elementAt(0)).getRenderedMessage());
    }

    /**
     * Sends the objects to a SocketNode over a real socket, closes the client
     * side and waits for the node to finish.
     */
    private VectorAppender runSocketNode(final Object[] objects) throws Exception {
        Hierarchy hierarchy = new Hierarchy(new RootLogger(Level.DEBUG));
        VectorAppender appender = new VectorAppender();
        hierarchy.getRootLogger().addAppender(appender);

        ServerSocket serverSocket = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"));
        Socket client = null;
        Socket accepted = null;
        try {
            client = new Socket(InetAddress.getByName("127.0.0.1"), serverSocket.getLocalPort());
            accepted = serverSocket.accept();

            ObjectOutputStream oos = new ObjectOutputStream(client.getOutputStream());
            for (int i = 0; i < objects.length; i++) {
                oos.writeObject(objects[i]);
            }
            oos.flush();
            client.shutdownOutput();

            Thread t = new Thread(new SocketNode(accepted, hierarchy));
            t.setDaemon(true);
            t.start();
            t.join(TIMEOUT_MS);
            assertFalse("SocketNode still deserializing after " + TIMEOUT_MS + " ms", t.isAlive());
        } finally {
            if (client != null) {
                client.close();
            }
            if (accepted != null) {
                accepted.close();
            }
            serverSocket.close();
        }
        return appender;
    }

    /**
     * Calls readAdaptedObject() on another thread so that an unprotected
     * stream, stuck in the exponential hashCode() computation, makes the
     * test fail rather than hang the build.
     *
     * @return the exception the read ended with
     */
    private static Throwable readAdaptedInBackground(final HardenedObjectInputStream hois)
            throws InterruptedException {
        final Throwable[] outcome = new Throwable[1];
        Thread t = new Thread(new Runnable() {
            public void run() {
                try {
                    hois.readAdaptedObject();
                } catch (Throwable e) {
                    outcome[0] = e;
                }
            }
        });
        t.setDaemon(true);
        t.start();
        t.join(TIMEOUT_MS);
        assertFalse("Still deserializing nested collections after " + TIMEOUT_MS + " ms", t.isAlive());
        return outcome[0];
    }

    private static void assertCollectionLimitHit(final Throwable t) {
        assertNotNull("Nested collections should have been rejected", t);
        assertTrue(String.valueOf(t), t instanceof InvalidObjectException);
        assertTrue(t.getMessage(), t.getMessage().indexOf("collection") >= 0);
    }

    private static LoggingEvent makeEvent(final String message, final Hashtable mdc) {
        Logger logger = Logger.getLogger("org.apache.log4j.net.HardenedObjectInputStreamTest");
        return new LoggingEvent(Logger.class.getName(), logger, System.currentTimeMillis(), Level.INFO,
                message, "main", null, null, null, mdc);
    }

    /** Same shape as the payload of testDeeplyNestedHashSetRejected. */
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
     * The nested payload rebuilt from Hashtables. Every table of a level holds
     * both tables of the next level as values, so hashCode() of the top table
     * visits about 2^depth tables. The top table is a key of the returned
     * Hashtable, which makes deserialization compute that hashCode(). Tables
     * are filled top-down, after being inserted, so building it stays cheap.
     */
    private static Map nestedHashtables(final int depth) {
        Map top = new Hashtable();
        Map root = new Hashtable();
        root.put(top, "payload");
        Map[] level = new Map[] { top };
        for (int i = 0; i < depth; i++) {
            Map a = new Hashtable();
            Map b = new Hashtable();
            for (int j = 0; j < level.length; j++) {
                level[j].put("a", a);
                level[j].put("b", b);
            }
            level = new Map[] { a, b };
        }
        for (int j = 0; j < level.length; j++) {
            level[j].put("foo", "bar");
        }
        return root;
    }

    /** A list holding the given number of empty lists: size + 1 collections. */
    private static List listOfLists(final int size) {
        List outer = new ArrayList();
        for (int i = 0; i < size; i++) {
            outer.add(new ArrayList());
        }
        return outer;
    }
}
