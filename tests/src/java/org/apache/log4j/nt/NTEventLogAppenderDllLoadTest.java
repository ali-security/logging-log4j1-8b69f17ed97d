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

package org.apache.log4j.nt;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.PrintStream;
import java.net.URL;
import java.net.URLClassLoader;

import junit.framework.TestCase;
import org.apache.log4j.AppenderSkeleton;


/**
 * DLL preloading (DLL hijacking) tests for the way NTEventLogAppender
 * locates its native DLL. These tests run on any platform.
 *
 * <p>Each test initializes NTEventLogAppender in a fresh class loader so that its
 * static initializer, which loads the DLL, runs again, and inspects what the
 * initializer reports on System.err. On hosts where no NTEventLogAppender DLL can be
 * loaded the initializer ends with an UnsatisfiedLinkError, which is expected.
 */
public class NTEventLogAppenderDllLoadTest extends TestCase {

  private static final String DLL_PATH_PROPERTY = "log4j.nteventlog.dll.path";

  private static final String APPENDER_CLASS = "org.apache.log4j.nt.NTEventLogAppender";

  private static final String CONFIGURED_LOAD_ATTEMPTED =
      "Failed to load NTEventLogAppender DLL from configured path";

  private String originalDllPath;

  public NTEventLogAppenderDllLoadTest(final String name) {
    super(name);
  }

  public void setUp() {
    originalDllPath = System.getProperty(DLL_PATH_PROPERTY);
  }

  public void tearDown() {
    if (originalDllPath != null) {
      System.setProperty(DLL_PATH_PROPERTY, originalDllPath);
    } else {
      System.getProperties().remove(DLL_PATH_PROPERTY);
    }
  }

  /**
   * Runs the NTEventLogAppender static initializer in a new class loader.
   * @return what the initializer printed on System.err.
   */
  private static String initializeAppenderClass() throws Exception {
    // AppenderSkeleton comes from the same location as NTEventLogAppender;
    // NTEventLogAppender itself must not be initialized by the test class loader.
    URL classes = AppenderSkeleton.class.getProtectionDomain().getCodeSource().getLocation();
    ClassLoader loader = new URLClassLoader(new URL[] { classes }, null);
    ByteArrayOutputStream captured = new ByteArrayOutputStream();
    PrintStream originalErr = System.err;
    System.setErr(new PrintStream(captured, true));
    try {
      Class.forName(APPENDER_CLASS, true, loader);
    } catch (LinkageError e) {
      // no loadable NTEventLogAppender DLL on this host
    } finally {
      System.setErr(originalErr);
    }
    return captured.toString();
  }

  /**
   * An absolute DLL path configured through log4j.nteventlog.dll.path must be
   * loaded directly, before the PATH / java.library.path search in which a
   * planted DLL could be picked up.
   */
  public void testConfiguredAbsolutePathIsLoadedBeforeLibrarySearch() throws Exception {
    // not a real DLL, so loading it fails and the initializer reports the attempt
    File dll = File.createTempFile("NTEventLogAppender", ".dll");
    dll.deleteOnExit();
    try {
      System.setProperty(DLL_PATH_PROPERTY, dll.getAbsolutePath());
      String err = initializeAppenderClass();
      assertTrue(err, err.indexOf(CONFIGURED_LOAD_ATTEMPTED) >= 0);
    } finally {
      dll.delete();
    }
  }

  /**
   * A relative path is resolved against the working directory, where an attacker
   * could plant a DLL; it must never be loaded.
   */
  public void testRelativeConfiguredPathIsNotLoaded() throws Exception {
    File planted = new File("NTEventLogAppender.planted.dll");
    planted.createNewFile();
    planted.deleteOnExit();
    try {
      assertTrue(planted.exists());
      System.setProperty(DLL_PATH_PROPERTY, planted.getPath());
      String err = initializeAppenderClass();
      assertTrue(err, err.indexOf("is not absolute") >= 0);
      assertTrue(err, err.indexOf(CONFIGURED_LOAD_ATTEMPTED) < 0);
    } finally {
      planted.delete();
    }
  }
}
