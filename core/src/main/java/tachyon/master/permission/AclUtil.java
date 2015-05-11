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

package tachyon.master.permission;

import java.io.IOException;

import tachyon.Constants;
import tachyon.conf.TachyonConf;
import tachyon.master.permission.AclEntry.AclPermission;
import tachyon.security.UserGroupInformation;

public class AclUtil {
  private static final AclPermission[] ACL_PERMISSIONS = AclPermission.values();
  /**
   * Get user permission from a short
   * @param n, short permission, e.g. 777
   * @return user {@link AclPermission}
   */
  public static AclPermission toUserPermission(short n) {
    AclPermission[] v = ACL_PERMISSIONS;
    return v[(n >>> 6) & 7];
  }

  /**
   * Get group permission from a short
   * @param n, short permission, e.g. 777
   * @return group {@link AclPermission}
   */
  public static AclPermission toGroupPermission(short n) {
    AclPermission[] v = ACL_PERMISSIONS;
    return v[(n >>> 3) & 7];
  }

  /**
   * Get other permission from a short
   * @param n, short permission, e.g. 777
   * @return other {@link AclPermission}
   */
  public static AclPermission toOtherPermission(short n) {
    AclPermission[] v = ACL_PERMISSIONS;
    return v[n & 7];
  }

  /**
   * Get permission from a String
   * @param s, a String of permission, e.g. rwx
   * @return a {@link AclPermission} which SYMBOL equal s
   */
  public static AclPermission getPermission(String s) {
    AclPermission[] v = ACL_PERMISSIONS;
    for (AclPermission aclPermission : v) {
      if (aclPermission.mValue.equals(s)) {
        return aclPermission;
      }
    }
    return null;
  }

  /**
   * Format permission expression from a short
   * @param n, a short permission, e.g. 00777
   * @return a String: "rwxrwxrwx"
   */
  public static String formatPermission(short n) {
    return toUserPermission(n).mValue + toGroupPermission(n).mValue + toOtherPermission(n).mValue;
  }

  /**
   * Get umask from configuration
   * @param conf
   * @return umask
   */
  public static short getUMask(TachyonConf conf) {
    int umask = Constants.DEFAULT_FS_PERMISSIONS_UMASK;
    if (conf != null) {
      umask = conf.getInt(Constants.FS_PERMISSIONS_UMASK_KEY,
          Constants.DEFAULT_FS_PERMISSIONS_UMASK);
    }
    return (short)umask;
  }

  /**
   * Get the default Acl information for Inode
   * @param isFolder
   * @return Acl
   */
  public static Acl getDefault(UserGroupInformation ugi, TachyonConf conf, boolean isFolder) {
    Acl acl = new Acl.Builder().build(ugi.getShortUserName(),
        conf.get(Constants.FS_PERMISSIONS_SUPERGROUP, Constants.FS_PERMISSIONS_SUPERGROUP_DEFAULT),
        isFolder ? Constants.DEFAULT_DIR_PERMISSION : Constants.DEFAULT_FILE_PERMISSION);
    acl.umask(conf);
    return acl;
  }

  public static Acl getDefault(boolean isFolder) {
    UserGroupInformation ugi = null;
    try {
      ugi = UserGroupInformation.getTachyonLoginUser();
    } catch (IOException ioe) {
      throw new RuntimeException("can't get the ugi info", ioe);
    }
    return getDefault(ugi, new TachyonConf(), isFolder);
  }
}
