/*!
 * This program is free software; you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License, version 2.1 as published by the Free Software
 * Foundation.
 *
 * You should have received a copy of the GNU Lesser General Public License along with this
 * program; if not, you can obtain a copy at http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html
 * or from the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Lesser General Public License for more details.
 *
 * Copyright (c) 2002-2015 Pentaho Corporation..  All rights reserved.
 */
package org.pentaho.platform.plugin.services.security.authentication;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.userdetails.UserDetails;

public class SpringSecurityInMemoryAuthTest extends AbstractSpringSecurityAuth {

  private final Log logger = LogFactory.getLog( SpringSecurityInMemoryAuthTest.class );


  public SpringSecurityInMemoryAuthTest() {
  }

  @Override public String getId() {
    return "memory";
  }

  @Override public Log getLogger() {
    return logger;
  }

  @Override UserDetails getValidUser() {
    return new DummyUserDetails( "memoryUser", "memoryPassword", new String[] { "Authenticated", "MemoryRole" } );
  }

  @Override UserDetails getBogusUser() {
    return new DummyUserDetails( "bogusUser", "bogusPassword", new String[] { "BogusRole" } );
  }

}
