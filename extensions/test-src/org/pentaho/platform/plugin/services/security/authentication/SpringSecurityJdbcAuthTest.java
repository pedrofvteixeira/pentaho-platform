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
import org.pentaho.platform.api.engine.ObjectFactoryException;
import org.pentaho.platform.engine.security.DefaultRoleJdbcDaoImpl;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.util.Arrays;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SpringSecurityJdbcAuthTest extends AbstractSpringSecurityAuth {

  private final Log logger = LogFactory.getLog( SpringSecurityJdbcAuthTest.class );

  private DefaultRoleJdbcDaoImpl jdbcDaoImpl;
  private DummyPentahoRole role1, role2;

  public SpringSecurityJdbcAuthTest() {
  }

  @Override public String getId() {
    return "jdbc";
  }

  @Override public Log getLogger() {
    return logger;
  }

  @Before public void setup() throws Exception {

    super.setup();

    role1 = new DummyPentahoRole( "Authenticated" );
    role2 = new DummyPentahoRole( "jdbcRole" );

    jdbcDaoImpl = mock( DefaultRoleJdbcDaoImpl.class );

    when( jdbcDaoImpl.loadUserByUsername( getValidUser().getUsername() ) ).thenReturn(
        new DummyUserDetails( getValidUser().getUsername(), getValidUser().getPassword(),
            new String[] { role1.getName(), role2.getName() } ) );

    AuthenticationProvider authenticationProvider = getBean( DaoAuthenticationProvider.class, "daoAuthenticationProvider" );
    ( ( DaoAuthenticationProvider ) authenticationProvider ).setUserDetailsService( jdbcDaoImpl );

    getBean( ProviderManager.class, "authenticationManager" ).setProviders( Arrays.asList(  authenticationProvider ) );
  }

  @Override UserDetails getValidUser() {
    return new DummyUserDetails( "jdbcAdmin", "jdbcPassword", new String[] { role1.getName(), role2.getName() } );
  }

  @Override UserDetails getBogusUser() {
    return new DummyUserDetails( "bogusUser", "bogusPassword", new String[] { "BogusRole" } );
  }

  @Override
  protected UserDetailsService getUserDetailsService() throws ObjectFactoryException {

    getLogger().info( "Returning mocked jdbcDaoImpl" );
    return jdbcDaoImpl;
  }

  @After public void tearDown() throws Exception {

    super.tearDown();
    jdbcDaoImpl = null;
    role1 = null;
    role2 = null;
  }
}
