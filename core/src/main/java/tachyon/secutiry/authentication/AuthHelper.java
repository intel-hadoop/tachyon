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

package tachyon.secutiry.authentication;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;
import javax.security.sasl.AuthenticationException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;
import java.io.IOException;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.Map;

import org.apache.thrift.transport.TSaslServerTransport;
import org.apache.thrift.transport.TTransportFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import tachyon.Constants;

public class AuthHelper {
  private static final Logger LOG = LoggerFactory.getLogger(Constants.LOGGER_TYPE);

  static {
    Security.addProvider(new SaslPlainProvider());
  }

  public static class SaslPlainProvider extends Provider {

    public SaslPlainProvider() {
      super("TachyonSaslPlain", 1.0, "Tachyon Plain SASL provider");
      put("SaslServerFactory.PLAIN", SaslPlainServerFactory.class.getName());
    }
  }

  public static class SaslPlainServerFactory implements SaslServerFactory {

    @Override
    public SaslServer createSaslServer(String mechanism, String protocol, String serverName,
                                       Map<String, ?> props, CallbackHandler cbh) {
      if ("PLAIN".equals(mechanism)) {
        try {
          return new PlainSaslServer(cbh, protocol);
        } catch (SaslException e) {
          /* This is to fulfill the contract of the interface which states that an exception shall
             be thrown when a SaslServer cannot be created due to an error but null should be
             returned when a Server can't be created due to the parameters supplied. And the only
             thing PlainSaslServer can fail on is a non-supported authentication mechanism.
             That's why we return null instead of throwing the Exception */
          return null;
        }
      }
      return null;
    }

    @Override
    public String[] getMechanismNames(Map<String, ?> props) {
      return new String[] {"PLAIN"};
    }
  }

  public static class PlainSaslServer implements SaslServer {
    private String mUser;
    private final CallbackHandler mHandler;

    PlainSaslServer(CallbackHandler mHandler, String authMethodStr) throws SaslException {
      this.mHandler = mHandler;
    }

    @Override
    public String getMechanismName() {
      return "PLAIN";
    }

    @Override
    public byte[] evaluateResponse(byte[] response) throws SaslException {
      try {
        // parse the response
        // message   = [authzid] UTF8NUL authcid UTF8NUL passwd'

        Deque<String> tokenList = new ArrayDeque<String>();
        StringBuilder messageToken = new StringBuilder();
        for (byte b : response) {
          if (b == 0) {
            tokenList.addLast(messageToken.toString());
            messageToken = new StringBuilder();
          } else {
            messageToken.append((char) b);
          }
        }
        tokenList.addLast(messageToken.toString());

        // validate response
        if (tokenList.size() < 2 || tokenList.size() > 3) {
          throw new SaslException("Invalid message format");
        }
        String passwd = tokenList.removeLast();
        mUser = tokenList.removeLast();
        // optional authzid
        String authzId;
        if (tokenList.isEmpty()) {
          authzId = mUser;
        } else {
          authzId = tokenList.removeLast();
        }
        if (mUser == null || mUser.isEmpty()) {
          throw new SaslException("No user name provided");
        }
        if (passwd == null || passwd.isEmpty()) {
          throw new SaslException("No password name provided");
        }

        NameCallback nameCallback = new NameCallback("User");
        nameCallback.setName(mUser);
        PasswordCallback pcCallback = new PasswordCallback("Password", false);
        pcCallback.setPassword(passwd.toCharArray());
        AuthorizeCallback acCallback = new AuthorizeCallback(mUser, authzId);

        Callback[] cbList = {nameCallback, pcCallback, acCallback};
        mHandler.handle(cbList);
        if (!acCallback.isAuthorized()) {
          throw new SaslException("Authentication failed");
        }
      } catch (IllegalStateException eL) {
        throw new SaslException("Invalid message format", eL);
      } catch (IOException eI) {
        throw new SaslException("Error validating the login", eI);
      } catch (UnsupportedCallbackException eU) {
        throw new SaslException("Error validating the login", eU);
      }
      return null;
    }

    @Override
    public boolean isComplete() {
      return mUser != null;
    }

    @Override
    public String getAuthorizationID() {
      return mUser;
    }

    @Override
    public byte[] unwrap(byte[] incoming, int offset, int len) {
      throw new UnsupportedOperationException();
    }

    @Override
    public byte[] wrap(byte[] outgoing, int offset, int len) {
      throw new UnsupportedOperationException();
    }

    @Override
    public Object getNegotiatedProperty(String propName) {
      return null;
    }

    @Override
    public void dispose() {}
  }

  public static TTransportFactory getAuthTransFactory() throws LoginException {
    TTransportFactory tTransportFactory;
    String authType = "NONE";

    // TODO: 1. kerbores 2. ...

    // the original code - no sasl

    // 3. Plain Sasl
    TSaslServerTransport.Factory saslFactory = new TSaslServerTransport.Factory();
    try {
      saslFactory.addServerDefinition("PLAIN", authType, null, new HashMap<String, String>(),
          new PlainServerCallbackHandler(authType));
    } catch (AuthenticationException e) {
      throw new LoginException("Error setting callback handler" + e);
    }
    return saslFactory;
  }

  private static final class PlainServerCallbackHandler implements CallbackHandler {

    //private final AuthMethods authMethod;

    PlainServerCallbackHandler(String authMethodStr) throws AuthenticationException {
      //authMethod = AuthMethods.getValidAuthMethod(authMethodStr);
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
      String username = null;
      String password = null;
      AuthorizeCallback ac = null;
      
      for (Callback callback : callbacks) {
        if (callback instanceof NameCallback) {
          NameCallback nc = (NameCallback) callback;
          username = nc.getName();
        } else if (callback instanceof PasswordCallback) {
          PasswordCallback pc = (PasswordCallback) callback;
          password = new String(pc.getPassword());
        } else if (callback instanceof AuthorizeCallback) {
          ac = (AuthorizeCallback) callback;
        } else {
          throw new UnsupportedCallbackException(callback);
        }
      }

      //TODO: add under layer authentication
//      PasswdAuthenticationProvider provider =
//          AuthenticationProviderFactory.getAuthenticationProvider(authMethod);
//      provider.Authenticate(username, password);
      if (ac != null) {
        ac.setAuthorized(true);
      }
      LOG.info("MY PATTERN: user is " + username + " , password is " + password);
    }
  }
}
