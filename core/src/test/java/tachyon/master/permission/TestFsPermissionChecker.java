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

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.BeforeClass;
import org.junit.Test;

import tachyon.Constants;
import tachyon.TachyonURI;
import tachyon.master.Inode;
import tachyon.master.InodeFile;
import tachyon.master.InodeFolder;
import tachyon.master.InodesInPath;
import tachyon.master.MasterInfo;
import tachyon.master.permission.AclEntry.AclPermission;
import tachyon.master.permission.AclEntry.AclType;
import tachyon.security.AuthenticationProvider;
import tachyon.thrift.AccessControlException;

import com.google.common.collect.Sets;

/** Unit tests covering TestFsPermissionChecker */
public class TestFsPermissionChecker {
  private static final String SUPERGROUP = "supergroup";
  private static final String SUPERUSER = "superuser";

  private static final Map<String, Set<String>> userToGroupsMapping =
      new HashMap<String,Set<String>>();
  static{
    userToGroupsMapping.put("bruce", Sets.newHashSet(""));
    userToGroupsMapping.put("diana", Sets.newHashSet("sales"));
    userToGroupsMapping.put("leo", Sets.newHashSet("devels"));
    userToGroupsMapping.put("clark", Sets.newHashSet("execs"));
  }

  private static final AtomicInteger inodeCounter = new AtomicInteger(0);
  private static InodeFolder inodeRoot;

  private static final MockAuthenticator BRUCE = new MockAuthenticator("bruce",
                                                     userToGroupsMapping);
  private static final MockAuthenticator DIANA = new MockAuthenticator("diana",
                                                     userToGroupsMapping);
  private static final MockAuthenticator LEO = new MockAuthenticator("leo",
                                                   userToGroupsMapping);
  private static final MockAuthenticator CLARK = new MockAuthenticator("clark",
                                                     userToGroupsMapping);

  @BeforeClass
  public static void setup() throws IOException {
    inodeRoot = createInodeDirectory(null, "", SUPERUSER, SUPERGROUP, Constants.DEFAULT_DIR_PERMISSION);
  }

  private static InodeFile createInodeFile(InodeFolder parent, String name,
      String owner, String group, short permission) throws IOException {
    InodeFile inodeFile = new InodeFile(name, inodeCounter.getAndIncrement(), parent.getId(),
                          Constants.DEFAULT_BLOCK_SIZE_BYTE, System.currentTimeMillis());

    inodeFile.setAcl(createAcl(uAclEntry(owner, AclUtil.toUserPermission(permission)),
        gAclEntry(group, AclUtil.toGroupPermission(permission)),
        oAclEntry(AclUtil.toOtherPermission(permission))));

    parent.addChild(inodeFile);
    return inodeFile;
  }

  private static InodeFolder createInodeDirectory(InodeFolder parent,
      String name, String owner, String group, short permission) throws IOException {
    InodeFolder inodeFolder = new InodeFolder(name, inodeCounter.getAndIncrement(),
        parent != null ? parent.getId() : -1,
        System.currentTimeMillis());

    inodeFolder.setAcl(createAcl(uAclEntry(owner, AclUtil.toUserPermission(permission)),
        gAclEntry(group, AclUtil.toGroupPermission(permission)),
        oAclEntry(AclUtil.toOtherPermission(permission))));

    if (parent != null) {
      parent.addChild(inodeFolder);
    }
    return inodeFolder;
  }

  private static Acl createAcl(AclEntry u, AclEntry g, AclEntry o) {
    Acl acl = new Acl.Builder().setUserEntry(u).setGroupEntry(g).setOtherEntry(o).build();
    acl.umask((short)Constants.DEFAULT_FS_PERMISSIONS_UMASK);
    return acl;
  }

  private static AclEntry uAclEntry(String name, AclPermission perm) {
    return aclEntry(AclType.USER, name, perm);
  }

  private static AclEntry gAclEntry(String name, AclPermission perm) {
    return aclEntry(AclType.GROUP, name, perm);
  }

  private static AclEntry oAclEntry(AclPermission perm) {
    return aclEntry(AclType.OTHER, "", perm);
  }

  private static AclEntry aclEntry(AclType type, String name, AclPermission perm) {
    return new AclEntry.Builder().setType(type)
        .setName(name).setPermission(perm).build();
  }

  private static void updateUserPerm(Inode inode, AclPermission u) {
    Acl acl = inode.getAcl();
    acl.setPermission(toShort(u, acl.getGroupPermission(), acl.getOtherPermission()));
  }

  private static void updateGroupPerm(Inode inode, AclPermission g) {
    Acl acl = inode.getAcl();
    acl.setPermission(toShort(acl.getUserPermission(), g, acl.getOtherPermission()));
  }

  private static void updateOtherPerm(Inode inode, AclPermission o) {
    Acl acl = inode.getAcl();
    acl.setPermission(toShort(acl.getUserPermission(), acl.getGroupPermission(), o));
  }

  private static short toShort(AclPermission u, AclPermission g, AclPermission o) {
    return (short)((u.ordinal() << 6) | (g.ordinal() << 3) | o.ordinal());
  }


  private void assertPermissionGranted(AuthenticationProvider authenticator, String path,
      boolean doCheckOwner,AclPermission access) throws IOException {
    try {
      InodesInPath iip = MasterInfo.resolve(inodeRoot, new TachyonURI(path));
      getPermissionChecker(authenticator).check(iip, doCheckOwner, null, null, access);
    } catch (AccessControlException e) {
      fail("unexpected AccessControlException for user: + " + authenticator.getUserName()
          + ", path = " + path);
    }
  }

  private void assertPermissionDenied(AuthenticationProvider authenticator, String path,
      boolean doCheckOwner,AclPermission access) throws IOException {
    try {
      InodesInPath iip = MasterInfo.resolve(inodeRoot, new TachyonURI(path));
      getPermissionChecker(authenticator).check(iip, doCheckOwner, null, null, access);
      fail("expected AccessControlException for user: + " + authenticator.getUserName()
          + ", path = " + path);
    } catch (AccessControlException e) {
      assertTrue("Permission denied messages and username must be catched",
              e.getMessage().contains("Permission denied") &&
              e.getMessage().contains(authenticator.getUserName()));
    }
  }

  private FsPermissionChecker getPermissionChecker(AuthenticationProvider authenticator) {
    return new FsPermissionChecker(SUPERUSER, SUPERGROUP, authenticator);
  }

  @Test
  public void testOwner() throws IOException {
    /**
     * -rw-r--r-- leo   sales  /file1
     * -rw-r--r-- diana devels /file2
     *
     * uid=bruce, groups=
     * uid=diana, groups=sales
     * uid=leo,   groups=devels
     * uid=clark, groups=execs
     */
    InodeFile inodeFile1 = createInodeFile(inodeRoot, "file1", "leo", "sales",
        Constants.DEFAULT_FILE_PERMISSION);
    InodeFile inodeFile2 = createInodeFile(inodeRoot, "file2", "diana", "devels",
        Constants.DEFAULT_FILE_PERMISSION);

    assertPermissionGranted(LEO, "/file1", true, null);
    assertPermissionDenied(DIANA, "/file1", true, null);

    assertPermissionGranted(DIANA, "/file2", true, null);
    assertPermissionDenied(LEO, "/file2", true, null);

    inodeFile1.getAcl().setUserOwner("diana");
    inodeFile2.getAcl().setUserOwner("leo");

    /**
     * -rw-r--r-- diana sales  /file1
     * -rw-r--r-- leo   devels /file2
     */

    assertPermissionGranted(DIANA, "/file1", true, null);
    assertPermissionDenied(LEO, "/file1", true, null);

    assertPermissionGranted(LEO, "/file2", true, null);
    assertPermissionDenied(DIANA, "/file2", true, null);
  }

  @Test
  public void testAclNamedUser() throws IOException {
    /**
     * -rw-r--r-- leo sales /file1
     *
     * uid=bruce, groups=
     * uid=diana, groups=sales
     * uid=leo,   groups=devels
     * uid=clark, groups=execs
     */
    InodeFile inodeFile1 = createInodeFile(inodeRoot, "file1", "leo", "sales",
        Constants.DEFAULT_FILE_PERMISSION);

    //user permission
    assertPermissionGranted(LEO, "/file1", false, AclPermission.READ);
    assertPermissionGranted(LEO, "/file1", false, AclPermission.WRITE);
    //group permission
    assertPermissionGranted(DIANA, "/file1", false, AclPermission.READ);
    //other permission
    assertPermissionGranted(BRUCE, "/file1", false, AclPermission.READ);

    assertPermissionDenied(DIANA, "/file1", false, AclPermission.WRITE);
    assertPermissionDenied(BRUCE, "/file1", false, AclPermission.WRITE);

    /**
     * -rw-r--r-- diana sales /file1
     */
    inodeFile1.getAcl().setUserOwner("diana");
    assertPermissionDenied(LEO, "/file1", false, AclPermission.WRITE);
    assertPermissionGranted(DIANA, "/file1", false, AclPermission.WRITE);
  }

  @Test
  public void testAclNamedUserDeny() throws IOException {
    /**
     * -rw-r--r-- leo devels /file1
     *
     * uid=bruce, groups=
     * uid=diana, groups=sales
     * uid=leo,   groups=devels
     * uid=clark, groups=execs
     */
    InodeFile inodeFile1 = createInodeFile(inodeRoot, "file1", "leo", "devels",
        Constants.DEFAULT_FILE_PERMISSION);

    assertPermissionGranted(LEO, "/file1", false, AclPermission.WRITE);
    assertPermissionDenied(BRUCE, "/file1", false, AclPermission.WRITE);
    assertPermissionDenied(CLARK, "/file1", false, AclPermission.WRITE);
    assertPermissionDenied(DIANA, "/file1", false, AclPermission.WRITE);

    /**
     * -r--r--r-- leo devels /file1
     *
     */
    updateUserPerm(inodeFile1, AclPermission.READ);
    assertPermissionDenied(LEO, "/file1", false, AclPermission.WRITE);
  }

  @Test
  public void testAclGroup() throws IOException {
    /**
     * -rw-r--r-- leo   sales  /file1
     * -rw-r--r-- diana devels /file2
     *
     * uid=bruce, groups=
     * uid=diana, groups=sales
     * uid=leo,   groups=devels
     * uid=clark, groups=execs
     */
    InodeFile inodeFile1 = createInodeFile(inodeRoot, "file1", "leo", "sales",
        Constants.DEFAULT_FILE_PERMISSION);
    InodeFile inodeFile2 = createInodeFile(inodeRoot, "file2", "diana", "devels",
        Constants.DEFAULT_FILE_PERMISSION);

    assertPermissionDenied(DIANA, "/file1", false, AclPermission.WRITE);
    assertPermissionDenied(LEO, "/file2", false, AclPermission.WRITE);

    updateGroupPerm(inodeFile1, AclPermission.READ_WRITE);
    updateGroupPerm(inodeFile2, AclPermission.READ_WRITE);
    /**
     * -rw-rw-r-- leo   sales  /file1
     * -rw-rw-r-- diana devels /file2
     */
    assertPermissionGranted(DIANA, "/file1", false, AclPermission.WRITE);
    assertPermissionGranted(LEO, "/file2", false, AclPermission.WRITE);
  }

  @Test
  public void testAclGroupDeny() throws IOException {
    /**
     * -rw-r--r-- bruce   sales  /file1
     *
     * uid=bruce, groups=
     * uid=diana, groups=sales
     * uid=leo,   groups=devels
     * uid=clark, groups=execs
     */
    InodeFile inodeFile1 = createInodeFile(inodeRoot, "file1", "bruce", "sales",
        Constants.DEFAULT_FILE_PERMISSION);

    assertPermissionGranted(BRUCE, "/file1", false, AclPermission.WRITE);
    assertPermissionGranted(BRUCE, "/file1", false, AclPermission.READ);
    assertPermissionGranted(DIANA, "/file1", false, AclPermission.READ);

    assertPermissionDenied(DIANA, "/file1", false, AclPermission.WRITE);
    assertPermissionDenied(CLARK, "/file1", false, AclPermission.WRITE);
    assertPermissionDenied(LEO, "/file1", false, AclPermission.WRITE);
  }

  @Test
  public void testAclTraverse() throws IOException {
    /**
     * drwxr-xr-x clark devels  /dir1
     * drwxr-xr-x leo   execs /dir1/dir2
     *
     * uid=bruce, groups=
     * uid=diana, groups=sales
     * uid=leo,   groups=devels
     * uid=clark, groups=execs
     */
    InodeFolder inodeFolder1 = createInodeDirectory(inodeRoot, "dir1", "clark", "devels",
        Constants.DEFAULT_DIR_PERMISSION);

    InodeFolder inodeFolder2 = createInodeDirectory(inodeFolder1, "dir2", "leo", "execs",
        Constants.DEFAULT_DIR_PERMISSION);

    assertPermissionGranted(BRUCE, "/dir1/dir2", false, AclPermission.EXECUTE);
    assertPermissionGranted(DIANA, "/dir1/dir2", false, AclPermission.EXECUTE);
    assertPermissionGranted(LEO, "/dir1/dir2", false, AclPermission.EXECUTE);
    assertPermissionGranted(CLARK, "/dir1/dir2", false, AclPermission.EXECUTE);

    updateGroupPerm(inodeFolder2, AclPermission.READ);
    updateOtherPerm(inodeFolder2, AclPermission.READ);

    assertPermissionDenied(DIANA, "/dir1/dir2", false, AclPermission.EXECUTE);
    assertPermissionDenied(CLARK, "/dir1/dir2", false, AclPermission.EXECUTE);
    assertPermissionDenied(BRUCE, "/dir1/dir2", false, AclPermission.EXECUTE);
  }

  @Test
  public void testAclOther() throws IOException {
    /**
     * drwxr-xr-x diana sales  /dir1
     * -rw-r--r-- leo   devels /dir1/file1
     *
     * uid=bruce, groups=
     * uid=diana, groups=sales
     * uid=leo,   groups=devels
     * uid=clark, groups=execs
     */
    InodeFolder inodeFolder1 = createInodeDirectory(inodeRoot, "dir1", "diana", "sales",
        Constants.DEFAULT_DIR_PERMISSION);
    InodeFile inodeFile1 = createInodeFile(inodeFolder1, "file1", "leo", "devels",
        Constants.DEFAULT_FILE_PERMISSION);

    assertPermissionGranted(LEO, "/dir1/file1", false, AclPermission.WRITE);
    assertPermissionGranted(LEO, "/dir1/file1", false, AclPermission.READ);
    assertPermissionGranted(CLARK, "/dir1/file1", false, AclPermission.READ);
    assertPermissionDenied(CLARK, "/dir1/file1", false, AclPermission.WRITE);

    assertPermissionDenied(CLARK, "/dir1", false, AclPermission.WRITE);
    assertPermissionGranted(CLARK, "/dir1", false, AclPermission.READ);

    updateOtherPerm(inodeFolder1, AclPermission.ALL);

    /**
     * drwxr-xrwx diana sales  /file1
     * -rw-r--r-- leo   devels /file1/file2
     */
    assertPermissionGranted(CLARK, "/dir1", false, AclPermission.WRITE);
  }
  /**
   * This class is used for mocking the authentication for testing.
   */
  private static class MockAuthenticator implements AuthenticationProvider {
    private final String authenticator;
    private final Map<String, Set<String>> userToGroupsMapping;

    MockAuthenticator(String authenticator, Map<String, Set<String>> userToGroupsMapping) {
      this.authenticator = authenticator;
      this.userToGroupsMapping = userToGroupsMapping;
    }

    @Override
    public String getUserName() {
      return authenticator;
    }

    @Override
    public Set<String> getGroupNames() {
      return userToGroupsMapping.get(authenticator);
    }
  }
}
