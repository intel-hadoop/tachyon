/*
 * Licensed to the University of California, Berkeley under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The ASF licenses this file to You under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License. You may obtain a
 * copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package tachyon.security;

import java.io.IOException;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import tachyon.Constants;
import tachyon.conf.TachyonConf;

//TODO: user to group mapping
public class UserGroupInformation {
  private static final Logger LOG = LoggerFactory.getLogger(Constants.LOGGER_TYPE);

  private static AuthenticationMethod sAuthenticationMethod;

  private static final String OS_LOGIN_MODULE_NAME;
  private static final Class<? extends Principal> OS_PRINCIPAL_CLASS;

  private static final boolean WINDOWS =
      System.getProperty("os.name").startsWith("Windows");
  private static final boolean IS_64_BIT =
      System.getProperty("os.arch").contains("64");
  private static final boolean AIX = System.getProperty("os.name").equals("AIX");
  public static final String JAVA_VENDOR_NAME = System.getProperty("java.vendor");
  public static final boolean IBM_JAVA = JAVA_VENDOR_NAME.contains("IBM");

  static {
    OS_LOGIN_MODULE_NAME = getOSLoginModuleName();
    OS_PRINCIPAL_CLASS = getOsPrincipalClass();
  }

  //TODO: represent the user and group by a class
  private static User sUser;
  private Set<String> mGroups;

  /* Return the OS login module class name */
  private static String getOSLoginModuleName() {
    if (IBM_JAVA) {
      if (WINDOWS) {
        return IS_64_BIT ? "com.ibm.security.auth.module.Win64LoginModule"
            : "com.ibm.security.auth.module.NTLoginModule";
      } else if (AIX) {
        return IS_64_BIT ? "com.ibm.security.auth.module.AIX64LoginModule"
            : "com.ibm.security.auth.module.AIXLoginModule";
      } else {
        return "com.ibm.security.auth.module.LinuxLoginModule";
      }
    } else {
      return WINDOWS ? "com.sun.security.auth.module.NTLoginModule"
          : "com.sun.security.auth.module.UnixLoginModule";
    }
  }

  private static Class<? extends Principal> getOsPrincipalClass() {
    ClassLoader cl = ClassLoader.getSystemClassLoader();
    try {
      String principalClass = null;
      if (IBM_JAVA) {
        if (IS_64_BIT) {
          principalClass = "com.ibm.security.auth.UsernamePrincipal";
        } else {
          if (WINDOWS) {
            principalClass = "com.ibm.security.auth.NTUserPrincipal";
          } else if (AIX) {
            principalClass = "com.ibm.security.auth.AIXPrincipal";
          } else {
            principalClass = "com.ibm.security.auth.LinuxPrincipal";
          }
        }
      } else {
        principalClass = WINDOWS ? "com.sun.security.auth.NTUserPrincipal"
            : "com.sun.security.auth.UnixPrincipal";
      }
      return (Class<? extends Principal>) cl.loadClass(principalClass);
    } catch (ClassNotFoundException e) {
      LOG.error("Unable to find JAAS classes:" + e.getMessage());
    }
    return null;
  }

  public static enum AuthenticationMethod {
    SIMPLE;
    //TODO: add kerbores, ...
  }

  private static class TachyonJaasConfiguration extends Configuration{
    private static final Map<String, String> BASIC_JAAS_OPTIONS =
        new HashMap<String,String>();

    private static final AppConfigurationEntry OS_SPECIFIC_LOGIN =
        new AppConfigurationEntry(OS_LOGIN_MODULE_NAME,
            AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
            BASIC_JAAS_OPTIONS);
    private static final AppConfigurationEntry HADOOP_LOGIN =
        new AppConfigurationEntry(TachyonLoginModule.class.getName(),
            AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
            BASIC_JAAS_OPTIONS);

    private static final AppConfigurationEntry[] SIMPLE = new
        AppConfigurationEntry[]{OS_SPECIFIC_LOGIN, HADOOP_LOGIN};

    @Override
    public AppConfigurationEntry[] getAppConfigurationEntry(String appName) {
      if ("simple".equals(appName)) {
        return SIMPLE;
      }
      return null;
    }
  }

  public static class TachyonLoginModule implements LoginModule {
    Subject mSubject;

    @Override
    public boolean abort() throws LoginException {
      return true;
    }

    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler,
                           Map<String, ?> sharedState, Map<String, ?> options) {
      this.mSubject = subject;
    }

    @Override
    public boolean login() throws LoginException {
      return true;
    }

    @Override
    public boolean logout() throws LoginException {
      return false;
    }

    private <T extends Principal> T getCanonicalUser(Class<T> cls) {
      for (T user: mSubject.getPrincipals(cls)) {
        return user;
      }
      return null;
    }

    @Override
    public boolean commit() throws LoginException {
      if (!mSubject.getPrincipals(User.class).isEmpty()) {
        return true;
      }

      Principal user = null;

      //TODO: 1. kerbores, 2. env

      //use OS user
      if (user == null) {
        user = getCanonicalUser(OS_PRINCIPAL_CLASS);
      }

      if (user != null) {
        User userEntry = new User(user.getName());
        mSubject.getPrincipals().add(userEntry);
        return true;
      }

      throw new LoginException("Cannot find user");
    }
  }

  public static void initialize(TachyonConf conf) {
    sAuthenticationMethod = SecurityUtil.getAuthenticationMethod(conf);
  }

  public static void loginUserFromOS() throws IOException {
    try {
      Subject subject = new Subject();

      LoginContext loginContext = newLoginContext("simple", subject,
          new TachyonJaasConfiguration());
      loginContext.login();

      sUser = subject.getPrincipals(User.class).iterator().next();
    } catch (LoginException e) {
      throw new IOException("fail to login", e);
    }
  }

  public static User getTachyonLoginUser() {
    if (sUser == null) {
      LOG.warn("login user is not found");
    }
    return sUser;
  }

  private static LoginContext newLoginContext(String appName, Subject subject,
                                       Configuration conf) throws LoginException {
    Thread t = Thread.currentThread();
    ClassLoader oldCCL = t.getContextClassLoader();
    t.setContextClassLoader(TachyonLoginModule.class.getClassLoader());
    try {
      return new LoginContext(appName, subject, null, conf);
    } finally {
      t.setContextClassLoader(oldCCL);
    }
  }
}
