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
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.pentaho.platform.api.engine.ObjectFactoryException;
import org.pentaho.platform.api.engine.security.userroledao.IPentahoRole;
import org.pentaho.platform.api.engine.security.userroledao.IPentahoUser;
import org.pentaho.platform.api.mt.ITenant;
import org.pentaho.platform.engine.core.system.PentahoSessionHolder;
import org.pentaho.platform.engine.core.system.StandaloneSession;
import org.pentaho.test.platform.engine.core.MicroPlatform;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceResolvable;
import org.springframework.context.NoSuchMessageException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.GrantedAuthorityImpl;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.*;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public abstract class AbstractSpringSecurityAuth {

  private static final String SPRING_CONFIG_FILE_NAME = "pentaho-spring-beans.xml";
  private static final String BASE_PATH = "test-res/security/authentication";
  private static final String SOLUTION_FOLDER = "pentaho-solutions";
  private static final String SYSTEM_FOLDER = "system";

  private final Log logger = LogFactory.getLog( getClass() );

  private static MicroPlatform microPlatform;

  StandaloneSession session;

  abstract UserDetails getValidUser();

  abstract UserDetails getBogusUser();

  abstract UserDetailsService getMockUserDetailsService() throws Exception;

  abstract AuthenticationProvider getMockAuthenticationProvider() throws Exception;

  @Before public void setup() throws Exception {

    String solutionPath = BASE_PATH + "/" + SOLUTION_FOLDER + "/";
    String systemPath = solutionPath + "/" + SYSTEM_FOLDER;

    getLogger().info( "Initializing MicroPlatform for: " + solutionPath + " .." );

    microPlatform = new MicroPlatform( solutionPath );
    microPlatform.setSpringConfig( systemPath + "/" + SPRING_CONFIG_FILE_NAME );

    microPlatform.start();

    getLogger().info( "MicroPlatform for: " + solutionPath + " started" );

    session = new StandaloneSession();
    PentahoSessionHolder.setSession( session );

    ProviderManager manager = getBean( ProviderManager.class, "authenticationManager" );
    List<AuthenticationProvider> providers = new ArrayList<AuthenticationProvider>(2);
    providers.add( getMockAuthenticationProvider() );
    providers.add( getBean( AuthenticationProvider.class, "anonymousAuthenticationProvider" ) );
    manager.setProviders( providers );
  }

  @Test public void testValidUsername() throws Exception {

    UserDetails user = getValidUser();

    assertNotNull( user );
    assertNotNull( user.getUsername() );
    assertNotNull( user.getPassword() );
    assertNotNull( user.getAuthorities() );

    UserDetailsService service = getMockUserDetailsService();
    assertNotNull( service );

    getLogger().info( "Loading '" + user.getUsername() + "' .." );
    UserDetails userDetails = service.loadUserByUsername( user.getUsername() );
    assertNotNull( userDetails );
    assertTrue( userDetails.getUsername().equals( user.getUsername() ) );

  }

  @Test public void testValidUserAuthorities() throws Exception {

    UserDetails user = getValidUser();

    assertNotNull( user );
    assertNotNull( user.getUsername() );
    assertNotNull( user.getPassword() );
    assertNotNull( user.getAuthorities() );

    UserDetailsService service = getMockUserDetailsService();
    assertNotNull( service );

    getLogger().info( "Loading '" + user.getUsername() + "' .." );
    UserDetails userDetails = service.loadUserByUsername( user.getUsername() );
    assertNotNull( userDetails );
    assertNotNull( userDetails.getAuthorities() );

    getLogger().info( "Loading authorities for " + user.getUsername() + "' .." );

    List<String> validAuthorities = new ArrayList<String>();
    for ( GrantedAuthority authority : user.getAuthorities() ) {
      getLogger().info( "> " + authority.getAuthority() );
      validAuthorities.add( authority.getAuthority() );
    }

    boolean rolesMatch = false;

    for ( GrantedAuthority authority : userDetails.getAuthorities() ) {
      rolesMatch |= validAuthorities.contains( authority.getAuthority() );
    }

    assertTrue( rolesMatch );
  }

  @Test public void testValidUserAuthentication() throws Exception {

    UserDetails user = getValidUser();

    assertNotNull( user );
    assertNotNull( user.getUsername() );
    assertNotNull( user.getPassword() );
    assertNotNull( user.getAuthorities() );

    getLogger().info( "Fetching AuthenticationManager.class from MicroPlatform" );
    ProviderManager providerManager = getBean( ProviderManager.class, "authenticationManager" );
    assertNotNull( providerManager );
    assertNotNull( providerManager.getProviders() );
    assertTrue( providerManager.getProviders().size() > 0 );

    UsernamePasswordAuthenticationToken auth =
        new UsernamePasswordAuthenticationToken( user.getUsername(), user.getPassword() );

    Authentication result = null;

    try {

      result = providerManager.authenticate( auth );

    } catch ( BadCredentialsException e ) {

      // this is *not* the expected outcome
      getLogger().error( e );
      Assert.fail();
    }

    assertNotNull( result );
    assertTrue( result.isAuthenticated() );
    assertNotNull( result.getPrincipal() );
    assertTrue( result.getPrincipal() instanceof UserDetails );
    assertTrue( user.getUsername().equals( ( (UserDetails) result.getPrincipal() ).getUsername() ) );

    // NOTE: in new spring security, the Authentication result objects no longer includes the provided password
    // assertTrue( user.getPassword().equals( ( ( UserDetails ) result.getPrincipal() ).getPassword() ) );
  }

  @Test public void testInvalidUserAuthentication() throws Exception {

    UserDetails user = getValidUser();

    assertNotNull( user );
    assertNotNull( user.getUsername() );
    assertNotNull( user.getPassword() );
    assertNotNull( user.getAuthorities() );

    getLogger().info( "Fetching AuthenticationManager.class from MicroPlatform" );
    ProviderManager providerManager = getBean( ProviderManager.class, "authenticationManager" );
    assertNotNull( providerManager );
    assertNotNull( providerManager.getProviders() );
    assertTrue( providerManager.getProviders().size() > 0 );

    String wrongPass = "THIS_IS_AN_INCORRECT_PASSWORD"; /* purposely incorrect password */

    UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken( user.getUsername(), wrongPass );

    Authentication result = null;

    try {

      result = providerManager.authenticate( auth );

    } catch ( BadCredentialsException e ) {

      getLogger().info( "Received a BadCredentialsException, as expected" );
      return;
    }

    // this is *not* the expected outcome
    Assert.fail();
  }

  @Test public void testBogusUsername() throws Exception {

    UserDetails user = getBogusUser();

    assertNotNull( user );
    assertNotNull( user.getUsername() );
    assertNotNull( user.getPassword() );
    assertNotNull( user.getAuthorities() );

    UserDetailsService service = getMockUserDetailsService();
    assertNotNull( service );

    getLogger().info( "Loading '" + user.getUsername() + "' .." );

    UserDetails userDetails = null;

    try {

      userDetails = service.loadUserByUsername( user.getUsername() );

    } catch ( UsernameNotFoundException e ) {

      // this is the proper/expected outcome. All is well.
      getLogger().info( "'" + user.getUsername() + "' not found, as expected" );
      return;

    }

    // we should never have reached this part... last chance: userDetails *must* be null
    if ( userDetails != null ) {

      getLogger().info( "'" + user.getUsername() + "' found ?" );
      Assert.fail();
    }
  }

  @After public void tearDown() throws Exception {

    if ( microPlatform != null && microPlatform.isInitialized() ) {
      microPlatform.stop();
    }
  }

  protected <T extends Object> T getBean( Class<T> clazz, String key ) throws ObjectFactoryException {
    if ( key == null ) {
      return getMicroPlatform().getFactory().get( clazz, getSession() );
    } else {
      return getMicroPlatform().getFactory().get( clazz, key, getSession() );
    }
  }

  protected StandaloneSession getSession() {
    return session;
  }

  protected static MicroPlatform getMicroPlatform() {
    return microPlatform;
  }

  protected Log getLogger() {
    return logger;
  }

  protected class DummyUserDetails implements UserDetails {

    private String username;
    private String password;
    private GrantedAuthority[] authorities;

    public DummyUserDetails( String username, String password, final String... authorities ) {
      this.username = username;
      this.password = password;

      List<GrantedAuthority> grantedAuthorities = new ArrayList<GrantedAuthority>();

      if ( authorities != null ) {

        for ( final String authority : authorities ) {
          grantedAuthorities.add( new GrantedAuthorityImpl( authority ) );
        }
      }

      this.authorities = grantedAuthorities.toArray( new GrantedAuthority[] { } );
    }

    @Override public Collection<? extends GrantedAuthority> getAuthorities() {
      return Arrays.asList( authorities );
    }

    @Override public String getPassword() {
      return password;
    }

    @Override public String getUsername() {
      return username;
    }

    @Override public boolean isAccountNonExpired() {
      return true;
    }

    @Override public boolean isAccountNonLocked() {
      return true;
    }

    @Override public boolean isCredentialsNonExpired() {
      return true;
    }

    @Override public boolean isEnabled() {
      return true;
    }
  }

  protected class DummyPentahoUser implements IPentahoUser {

    private ITenant tenant;
    private String username;
    private String password;

    public DummyPentahoUser( final String username, final String password ) {

      this.username = username;
      this.password = password;
      this.tenant = new DummyPentahoTenant( "mock-tenant-id" );
    }

    @Override public String getUsername() {
      return username;
    }

    @Override public ITenant getTenant() {
      return tenant;
    }

    @Override public String getPassword() {
      return password;
    }

    @Override public void setPassword( String password ) {
    }

    @Override public boolean isEnabled() {
      return true;
    }

    @Override public void setEnabled( boolean enabled ) {
    }

    @Override public String getDescription() {
      return null;
    }

    @Override public void setDescription( String description ) {
    }
  }

  protected class DummyPentahoRole implements IPentahoRole {

    private ITenant tenant;
    private String name;

    public DummyPentahoRole( final String name ) {

      this.name = name;
      this.tenant = new DummyPentahoTenant( "mock-tenant-id" );
    }

    @Override public ITenant getTenant() {
      return tenant;
    }

    @Override public String getName() {
      return name;
    }

    @Override public String getDescription() {
      return null;
    }

    @Override public void setDescription( String description ) {
    }
  }

  protected class DummyPentahoTenant implements ITenant {

    private String tenantId;

    public DummyPentahoTenant( final String tenantId ) {
      this.tenantId = tenantId;
    }

    @Override public String getId() {
      return tenantId;
    }

    @Override public String getRootFolderAbsolutePath() {
      return null;
    }

    @Override public String getName() {
      return tenantId;
    }

    @Override public boolean isEnabled() {
      return true;
    }
  }

  protected class DummyUserDetailsChecker implements UserDetailsChecker {

    @Override public void check( UserDetails toCheck ) {
      return;
    }
  }

  protected class DummyMessageSource implements MessageSource {

    @Override public String getMessage( String s, Object[] objects, String s1, Locale locale ) {
      return null;
    }

    @Override public String getMessage( String s, Object[] objects, Locale locale ) throws NoSuchMessageException {
      return null;
    }

    @Override public String getMessage( MessageSourceResolvable messageSourceResolvable, Locale locale )
        throws NoSuchMessageException {
      return null;
    }
  }
}
