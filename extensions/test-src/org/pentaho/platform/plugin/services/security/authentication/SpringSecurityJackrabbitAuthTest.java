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
import org.junit.After;
import org.junit.Before;
import org.pentaho.platform.api.engine.security.userroledao.IPentahoRole;
import org.pentaho.platform.api.engine.security.userroledao.IUserRoleDao;
import org.pentaho.platform.security.userroledao.service.UserRoleDaoUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.util.Arrays;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SpringSecurityJackrabbitAuthTest extends AbstractSpringSecurityAuth {

  private final Log logger = LogFactory.getLog( SpringSecurityJackrabbitAuthTest.class );

  private IUserRoleDao userRoleDao;
  private DummyPentahoRole role1, role2;

  @Override public String getId() {
    return "jackrabbit";
  }

  @Override public Log getLogger() {
    return logger;
  }

  @Before public void setup() throws Exception {

    super.setup();

    role1 = new DummyPentahoRole( "Authenticated" );
    role2 = new DummyPentahoRole( "Administrator" );

    IUserRoleDao userRoleDao = mock( IUserRoleDao.class );

    when( userRoleDao.getUser( null, getValidUser().getUsername() ) )
        .thenReturn( new DummyPentahoUser( getValidUser().getUsername(), getValidUser().getPassword() ) );

    when( userRoleDao.getUserRoles( null, getValidUser().getUsername() ) )
        .thenReturn( Arrays.asList( new IPentahoRole[] { role1, role2 } ) );

    UserDetailsService userDetailsService = getBean( UserDetailsService.class, "jcrUserDetailsService" );
    ( (UserRoleDaoUserDetailsService) userDetailsService ).setUserRoleDao( userRoleDao );
  }

  @After public void tearDown() throws Exception {

    super.tearDown();
    userRoleDao = null;
    role1 = null;
    role2 = null;
  }

  @Override UserDetails getValidUser() {
    return new DummyUserDetails( "admin", "password", new String[] { role1.getName(), role2.getName() } );
  }

  @Override UserDetails getBogusUser() {
    return new DummyUserDetails( "bogusUser", "bogusPassword", new String[] { "BogusRole" } );
  }
}
