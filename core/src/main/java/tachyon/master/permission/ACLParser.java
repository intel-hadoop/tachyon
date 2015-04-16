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
 

package tachyon.master.permission;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import tachyon.Constants;

*//**
 * Acl Parser for {@link tachyon.master.permission.Acl}.
 *//*
public class ACLParser {

  private static final Log LOG = LogFactory.getLog(ACLParser.class);

  private static Pattern chmodOctalPattern =
      Pattern.compile("^\\s*[+]?([01]?)([0-7]{3})\\s*$");
  private static Pattern chmodNormalPattern =
      Pattern.compile("\\G\\s*([ugoa]*)([+=-]+)([rwxXt]+)([,\\s]*)\\s*");
    
  private Acl acl;

  *//**
   * Prevent instantiation
   *//*
  private ACLParser() {}

  public ACLParser(String modeStr) {
    Matcher matcher = null;
    if ((matcher = chmodNormalPattern.matcher(modeStr)).find()) {
      applyNormalPattern(modeStr, matcher);
    } else if ((matcher = chmodOctalPattern.matcher(modeStr)).matches()) {
      applyOctalPattern(modeStr, matcher);
    } else {
      throw new IllegalArgumentException(modeStr);
    }
  }

  private void applyOctalPattern(String modeStr, Matcher matcher) {
    userType = groupType = othersType = '=';

    // Check if sticky bit is specified
    String sb = matcher.group(1);
    if (!sb.isEmpty()) {
      stickyMode = Short.valueOf(sb.substring(0, 1));
      stickyBitType = '=';
    }

    String str = matcher.group(2);
    acl.setPermission(Short.valueOf(str.substring(0, 3)));
  }

  private void applyNormalPattern(String modeStr, Matcher matcher) {
    // Are there multiple permissions stored in one chmod?
    boolean commaSeperated = false;

    for (int i = 0; i < 1 || matcher.end() < modeStr.length(); i++) {
      if (i > 0 && (!commaSeperated || !matcher.find())) {
        throw new IllegalArgumentException(modeStr);
      }

      
       * groups : 1 : [ugoa]* 2 : [+-=] 3 : [rwxXt]+ 4 : [,\s]*
       

      String str = matcher.group(2);
      char type = str.charAt(str.length() - 1);

      boolean user, group, others, stickyBit;
      user = group = others = stickyBit = false;

      for (char c : matcher.group(1).toCharArray()) {
        switch (c) {
        case 'u':
          user = true;
          break;
        case 'g':
          group = true;
          break;
        case 'o':
          others = true;
          break;
        case 'a':
          break;
        default:
          throw new RuntimeException("Unexpected");
        }
      }

      if (!(user || group || others)) { // same as specifying 'a'
        user = group = others = true;
      }

      short mode = 0;

      for (char c : matcher.group(3).toCharArray()) {
        switch (c) {
        case 'r':
          mode |= 4;
          break;
        case 'w':
          mode |= 2;
          break;
        case 'x':
          mode |= 1;
          break;
        case 'X':
          mode |= 8;
          break;
        case 't':
          stickyBit = true;
          break;
        default:
          throw new RuntimeException("Unexpected");
        }
      }

      if (user) {
        userMode = mode;
        userType = type;
      }

      if (group) {
        groupMode = mode;
        groupType = type;
      }

      if (others) {
        othersMode = mode;
        othersType = type;

        stickyMode = (short) (stickyBit ? 1 : 0);
        stickyBitType = type;
      }

      commaSeperated = matcher.group(4).contains(",");
    }
    symbolic = true;
  }

  *//**
   * // TODO
   * Store the source {@link tachyon.conf.TachyonConf} object to the target
   * Hadoop {@link org.apache.hadoop.conf.Configuration} object.
   *
   * @param source the {@link tachyon.conf.TachyonConf} to be stored
   *//*
  public static int parsePermission(String mode) {
    return 0;
  }

}
*/