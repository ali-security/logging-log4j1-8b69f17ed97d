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
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;

import junit.framework.TestCase;

import org.apache.log4j.Hierarchy;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.VectorAppender;
import org.apache.log4j.spi.LocationInfo;
import org.apache.log4j.spi.LoggingEvent;
import org.apache.log4j.spi.RootLogger;
import org.apache.log4j.spi.ThrowableInformation;
import org.apache.log4j.xml.XLevel;

/**
 * Checks that {@link HardenedLoggingEventInputStream} (and therefore
 * {@link SocketNode}, used by {@link SocketServer} and
 * {@link SimpleSocketServer}) only deserializes logging events and refuses
 * any other class sent over the wire (CVE-2019-17571).
 */
public class HardenedLoggingEventInputStreamTest extends TestCase {

    public HardenedLoggingEventInputStreamTest(final String testName) {
        super(testName);
    }

    protected void setUp() {
        RecordingPayload.deserialized = false;
    }

    private static byte[] serialize(final Object o) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(o);
        oos.flush();
        oos.close();
        return bos.toByteArray();
    }

    private static Object readHardened(final byte[] bytes) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new HardenedLoggingEventInputStream(new ByteArrayInputStream(bytes));
        try {
            return ois.readObject();
        } finally {
            ois.close();
        }
    }

    private static void assertRejected(final InvalidClassException e, final String className) {
        String msg = e.getMessage();
        assertNotNull(msg);
        assertTrue(msg, msg.indexOf("Unauthorized deserialization attempt") >= 0);
        assertTrue(msg, msg.endsWith("; " + className));
    }

    private static LoggingEvent makeEvent(final Level level, final Hashtable mdc) {
        Logger logger = Logger.getLogger("org.apache.log4j.net.HardenedLoggingEventInputStreamTest");
        ThrowableInformation ti = new ThrowableInformation(new Exception("Just testing"));
        LocationInfo li = new LocationInfo("Foo.java", "org.example.Foo", "bar", "42");
        return new LoggingEvent(Logger.class.getName(), logger, System.currentTimeMillis(), level,
                "hello", "main", ti, "ndc-value", li, mdc);
    }

    /**
     * Regular logging events, including MDC, NDC, location and throwable
     * information, still go through the hardened stream.
     */
    public void testLoggingEventIsAccepted() throws Exception {
        Hashtable mdc = new Hashtable();
        mdc.put("key", "value");
        mdc.put("number", new Integer(5));

        Object o = readHardened(serialize(makeEvent(Level.WARN, mdc)));

        assertTrue(o instanceof LoggingEvent);
        LoggingEvent event = (LoggingEvent) o;
        assertEquals("org.apache.log4j.net.HardenedLoggingEventInputStreamTest", event.getLoggerName());
        assertEquals(Level.WARN, event.getLevel());
        assertEquals("hello", event.getRenderedMessage());
        assertEquals("main", event.getThreadName());
        assertEquals("ndc-value", event.getNDC());
        assertEquals("value", event.getMDC("key"));
        assertEquals(new Integer(5), event.getMDC("number"));
        assertEquals("42", event.getLocationInformation().getLineNumber());
        String[] rep = event.getThrowableStrRep();
        assertNotNull(rep);
        assertEquals("java.lang.Exception: Just testing", rep[0]);
    }

    /**
     * Custom levels travel as a class name, not as a serialized object, so
     * they keep working with the hardened stream.
     */
    public void testCustomLevelIsAccepted() throws Exception {
        Object o = readHardened(serialize(makeEvent(XLevel.TRACE, null)));

        assertTrue(o instanceof LoggingEvent);
        assertEquals(XLevel.TRACE, ((LoggingEvent) o).getLevel());
    }

    /**
     * A non whitelisted object sent instead of a logging event must be
     * rejected before its readObject method runs.
     */
    public void testBadPayloadIsRejected() throws Exception {
        byte[] bytes = serialize(new BadPayload("x"));
        try {
            readHardened(bytes);
            fail("BadPayload should not have been deserialized");
        } catch (InvalidClassException e) {
            assertRejected(e, BadPayload.class.getName());
        }
    }

    /**
     * A non whitelisted object hidden inside a logging event (here in the
     * MDC copy) must be rejected as well.
     */
    public void testPayloadNestedInLoggingEventIsRejected() throws Exception {
        Hashtable mdc = new Hashtable();
        mdc.put("key", new RecordingPayload());
        byte[] bytes = serialize(makeEvent(Level.INFO, mdc));
        try {
            readHardened(bytes);
            fail("RecordingPayload should not have been deserialized");
        } catch (InvalidClassException e) {
            assertRejected(e, RecordingPayload.class.getName());
        }
        assertFalse(RecordingPayload.deserialized);
    }

    /**
     * Arrays of non whitelisted classes must be rejected.
     */
    public void testArrayOfBadPayloadIsRejected() throws Exception {
        byte[] bytes = serialize(new BadPayload[] { new BadPayload("x") });
        try {
            readHardened(bytes);
            fail("BadPayload[] should not have been deserialized");
        } catch (InvalidClassException e) {
            assertRejected(e, "[L" + BadPayload.class.getName() + ";");
        }
    }

    /**
     * Classes may be explicitly authorized by the caller.
     */
    public void testAdditionalAuthorizedClasses() throws Exception {
        List authorized = new ArrayList();
        authorized.add(RecordingPayload.class.getName());
        ObjectInputStream ois = new HardenedLoggingEventInputStream(
                new ByteArrayInputStream(serialize(new RecordingPayload())), authorized);
        try {
            assertTrue(ois.readObject() instanceof RecordingPayload);
        } finally {
            ois.close();
        }
        assertTrue(RecordingPayload.deserialized);
    }

    /**
     * End to end: a SocketNode, as used by SocketServer and
     * SimpleSocketServer, logs genuine events but never deserializes an
     * arbitrary object sent by a remote client.
     */
    public void testSocketNodeDoesNotDeserializeArbitraryObjects() throws Exception {
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
            oos.writeObject(makeEvent(Level.INFO, null));
            oos.writeObject(new RecordingPayload());
            oos.flush();

            SocketNode node = new SocketNode(accepted, hierarchy);
            Thread t = new Thread(node);
            t.start();
            t.join(30000);
            assertFalse("SocketNode did not terminate", t.isAlive());
        } finally {
            if (client != null) {
                client.close();
            }
            if (accepted != null) {
                accepted.close();
            }
            serverSocket.close();
        }

        assertFalse("RecordingPayload was deserialized by SocketNode", RecordingPayload.deserialized);
        assertEquals(1, appender.getVector().size());
        assertEquals("hello", ((LoggingEvent) appender.getVector().elementAt(0)).getRenderedMessage());
    }

    /**
     * Serializable class that records whether it was ever deserialized.
     */
    public static class RecordingPayload implements Serializable {
        private static final long serialVersionUID = 1L;

        static volatile boolean deserialized = false;

        private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
            in.defaultReadObject();
            deserialized = true;
        }
    }
}
