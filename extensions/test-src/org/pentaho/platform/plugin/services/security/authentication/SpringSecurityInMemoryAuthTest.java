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

import org.junit.After;
import org.junit.Before;
import org.mockito.Mockito;
import org.pentaho.platform.api.mt.ITenantedPrincipleNameResolver;
import org.pentaho.platform.plugin.services.security.userrole.memory.DefaultInMemoryUserDetailsService;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.authentication.encoding.PlaintextPasswordEncoder;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.core.userdetails.memory.UserMap;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SpringSecurityInMemoryAuthTest extends AbstractSpringSecurityAuth {

  private UserDetailsService mockUserDetailsService;
  private AuthenticationProvider mockAuthProvider;

  @After public void tearDown() throws Exception {

    super.tearDown();

    mockUserDetailsService = null;
    mockAuthProvider = null;
  }

  @Override UserDetails getValidUser() {
    return new DummyUserDetails( "memoryUser", "password", new String[] { "Authenticated", "MemoryRole" } );
  }

  @Override UserDetails getBogusUser() {
    return new DummyUserDetails( "bogusUser", "password", new String[] { "BogusRole" } );
  }

  @Override AuthenticationProvider getMockAuthenticationProvider() throws Exception {

    if( mockAuthProvider == null ){

      /*
       * just because of the protected final logger object in AbstractUserDetailsAuthenticationProvider...
       * they REALLY should've created a getter and called upon that one instead of calling directly a final logger...
       */
      // mockAuthProvider = mock( DaoAuthenticationProvider.class , Mockito.CALLS_REAL_METHODS);
      mockAuthProvider = new DaoAuthenticationProvider();

      ( ( DaoAuthenticationProvider ) mockAuthProvider ).setMessageSource( new DummyMessageSource() );
      ( ( DaoAuthenticationProvider ) mockAuthProvider ).setAuthoritiesMapper( new NullAuthoritiesMapper() );
      ( ( DaoAuthenticationProvider ) mockAuthProvider ).setUserDetailsService( getMockUserDetailsService() );
      ( ( DaoAuthenticationProvider ) mockAuthProvider ).setPasswordEncoder( new PlaintextPasswordEncoder() );
      ( ( DaoAuthenticationProvider ) mockAuthProvider ).setPreAuthenticationChecks( new DummyUserDetailsChecker() );
      ( ( DaoAuthenticationProvider ) mockAuthProvider ).setPostAuthenticationChecks( new DummyUserDetailsChecker() );

      UserCache userCache = mock( UserCache.class );
      when( userCache.getUserFromCache( Mockito.anyString() ) ).thenReturn( null );
      ( ( DaoAuthenticationProvider ) mockAuthProvider ).setUserCache( userCache );
    }

    return mockAuthProvider;
  }

  @Override UserDetailsService getMockUserDetailsService() throws Exception {

    if( mockUserDetailsService == null ) {

      ITenantedPrincipleNameResolver userNameUtils = mock( ITenantedPrincipleNameResolver.class );
      when( userNameUtils.getPrincipleName( getValidUser().getUsername() ) ).thenReturn( getValidUser().getUsername() );
      when( userNameUtils.getPrincipleName( getBogusUser().getUsername() ) ).thenReturn( getBogusUser().getUsername() );

      mockUserDetailsService = new DefaultInMemoryUserDetailsService( userNameUtils );
      UserMap map = new UserMap();
      map.addUser( getValidUser() );

      ( ( DefaultInMemoryUserDetailsService ) mockUserDetailsService ).setUserMap( map );
    }

    return mockUserDetailsService;
  }
}
