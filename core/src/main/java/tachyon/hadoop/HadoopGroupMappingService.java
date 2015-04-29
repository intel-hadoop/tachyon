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

package tachyon.hadoop;

import java.io.IOException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.security.Groups;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import tachyon.security.GroupMappingServiceProvider;

public class HadoopGroupMappingService implements GroupMappingServiceProvider {
  private static final Logger LOGGER = LoggerFactory.getLogger(HadoopGroupMappingService.class);
  private Groups mGroups;

  public HadoopGroupMappingService() {
    this(Groups.getUserToGroupsMappingService(new Configuration()));
  }

  public HadoopGroupMappingService(Groups group) {
    mGroups = group;
  }

  @Override
  public Set<String> getGroups(String user) throws IOException {
    try {
      return new HashSet<String>(mGroups.getGroups(user));
    } catch (IOException e) {
      LOGGER.warn("Unable to obtain groups for " + user, e);
    }
    return Collections.emptySet();
  }
}
