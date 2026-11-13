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
import java.util.List;

import javax.naming.Context;
import javax.naming.NamingException;



/**
 * Test copied form the logback project with permission.
 *
 * @author Ceki Gulcu
 *
 */
public class JNDIUtilTest extends TestCase {

  public void testEnsureJavaNameSpace() throws NamingException {

    try {
      Context ctxt = JNDIUtil.getInitialContext();
      JNDIUtil.lookupObject(ctxt, "ldap:...");
    } catch (NamingException e) {
      String excaptionMsg = e.getMessage();
      if (excaptionMsg.startsWith(JNDIUtil.RESTRICTION_MSG))
        return;
      else {
        assertTrue(false);
      }
    }

    assertTrue(false);
  }

  /**
   * Names pointing at remote naming services (the JNDI injection
   * payloads) must be refused before the context is ever asked to
   * resolve them.
   */
  public void testRemoteNamesAreRejectedBeforeLookup() {
    String[] payloads = {
        "ldap://attacker.example:1389/Exploit",
        "ldaps://attacker.example:1636/Exploit",
        "LDAP://attacker.example:1389/Exploit",
        "rmi://attacker.example:1099/Exploit",
        "iiop://attacker.example:1050/Exploit",
        "corbaname:iiop:attacker.example:1050#Exploit",
        "dns://attacker.example/Exploit",
        " java:comp/env/../ldap://attacker.example:1389/Exploit",
        "JAVA:comp/env/jms/TCF",
        "Exploit"
    };
    List lookups = new ArrayList();
    Context ctx = recordingContext(lookups);
    for (int i = 0; i < payloads.length; i++) {
      try {
        JNDIUtil.lookupObject(ctx, payloads[i]);
        fail("lookup of [" + payloads[i] + "] should have been refused");
      } catch (NamingException e) {
        assertEquals(JNDIUtil.RESTRICTION_MSG + payloads[i], e.getMessage());
      }
    }
    assertEquals("context must never see a remote name", 0, lookups.size());
  }

  public void testJavaNamespaceLookupIsDelegated() throws NamingException {
    List lookups = new ArrayList();
    Context ctx = recordingContext(lookups);
    assertEquals("java:comp/env/jms/TCF",
        JNDIUtil.lookupObject(ctx, "java:comp/env/jms/TCF"));
    assertEquals(1, lookups.size());
    assertEquals("java:comp/env/jms/TCF", lookups.get(0));
  }

  public void testNullOrEmptyInputsAreNotLookedUp() throws NamingException {
    List lookups = new ArrayList();
    Context ctx = recordingContext(lookups);
    assertNull(JNDIUtil.lookupObject(null, "java:comp/env/jms/TCF"));
    assertNull(JNDIUtil.lookupObject(ctx, null));
    assertNull(JNDIUtil.lookupObject(ctx, ""));
    assertNull(JNDIUtil.lookupObject(ctx, "   "));
    assertEquals(0, lookups.size());
  }

  /**
   * Returns a Context that records every name it is asked to resolve
   * and answers with the name itself.
   */
  private static Context recordingContext(final List lookups) {
    return (Context) Proxy.newProxyInstance(
        JNDIUtilTest.class.getClassLoader(),
        new Class[] { Context.class },
        new InvocationHandler() {
          public Object invoke(Object proxy, Method method, Object[] args) {
            if ("lookup".equals(method.getName())) {
              String name = String.valueOf(args[0]);
              lookups.add(name);
              return name;
            }
            if ("hashCode".equals(method.getName())) {
              return new Integer(System.identityHashCode(proxy));
            }
            if ("equals".equals(method.getName())) {
              return (proxy == args[0]) ? Boolean.TRUE : Boolean.FALSE;
            }
            if ("toString".equals(method.getName())) {
              return "RecordingContext";
            }
            return null;
          }
        });
  }
}
