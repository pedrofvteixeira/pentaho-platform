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
import org.junit.Ignore;
import org.pentaho.platform.api.engine.ObjectFactoryException;
import org.pentaho.platform.engine.security.DefaultRoleUserDetailsServiceDecorator;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

@Ignore
public class SpringSecurityLdapIntegrationAuthTest extends AbstractSpringSecurityAuth {

  private final Log logger = LogFactory.getLog( SpringSecurityLdapIntegrationAuthTest.class );

  private DummyPentahoRole role1, role2, role3;

  public SpringSecurityLdapIntegrationAuthTest() {
  }

  @Before public void setup() throws Exception {

    super.setup();

    role1 = new DummyPentahoRole( "Authenticated" );
    role2 = new DummyPentahoRole( "Administrator" );
    role3 = new DummyPentahoRole( "ceo" );
  }

  @Override public String getId() {
    return "ldap";
  }

  @Override public Log getLogger() {
    return logger;
  }

  @Override UserDetails getValidUser() {
    return new DummyUserDetails( "admin", "password",
        new String[] { role1.getName(), role2.getName(), role3.getName() } );
  }

  @Override UserDetails getBogusUser() {
    return new DummyUserDetails( "bogusUser", "bogusPassword", new String[] { "bogusRole" } );
  }

  @Override protected UserDetailsService getUserDetailsService() throws ObjectFactoryException {

    getLogger().info( "Returning ldapUserDetailsService" );
    return getBean( DefaultRoleUserDetailsServiceDecorator.class, "ldapUserDetailsService" );
  }

  @After public void tearDown() throws Exception {

    super.tearDown();
    role1 = null;
    role2 = null;
    role3 = null;
  }

}
