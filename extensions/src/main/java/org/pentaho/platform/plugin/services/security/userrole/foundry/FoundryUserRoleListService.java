package org.pentaho.platform.plugin.services.security.userrole.foundry;

import org.pentaho.platform.api.engine.IUserRoleListService;
import org.pentaho.platform.api.mt.ITenant;
import org.pentaho.platform.api.mt.ITenantedPrincipleNameResolver;
import org.pentaho.platform.repository2.unified.jcr.JcrTenantUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.util.*;

/**
 * Created by jchilton on 9/18/2017.
 */
public class FoundryUserRoleListService implements IUserRoleListService {

  /**
   * Case-sensitive by default.
   */
  private Comparator<String> roleComparator;
  private UserDetailsService userDetailsService;
  private ITenantedPrincipleNameResolver userNameUtils;
  private List<String> extraRoles;

  @Override
  public List<String> getAllRoles() {
    return null;
  }

  @Override
  public List<String> getSystemRoles() {
    return null;
  }

  @Override
  public List<String> getAllRoles(ITenant tenant) {
    return null;
  }

  @Override
  public List<String> getAllUsers() {
    return null;
  }

  @Override
  public List<String> getAllUsers(ITenant tenant) {
    return null;
  }

  @Override
  public List<String> getUsersInRole(ITenant tenant, String role) {
    return null;
  }

  @Override
  public List<String> getRolesForUser(ITenant tenant, String username) {
    if ( tenant != null && !tenant.equals( JcrTenantUtils.getDefaultTenant() ) ) {
      throw new UnsupportedOperationException( "only allowed to access to default tenant" );
    }
    UserDetails user = userDetailsService.loadUserByUsername( userNameUtils.getPrincipleName( username ) );
    Collection<? extends GrantedAuthority> results = user.getAuthorities();
    Set<String> roles = ( roleComparator != null ) ? new TreeSet<String>( roleComparator ) : new LinkedHashSet<String>( results.size() );
    for ( GrantedAuthority role : results ) {
      roles.add( role.getAuthority() );
    }
    // Now add extra role if it does not exist in the list
    for ( String extraRole : extraRoles ) {
      roles.add( extraRole );
    }

    return new ArrayList<String>( roles );
  }

  public UserDetailsService getUserDetailsService() {
    return userDetailsService;
  }

  public void setUserDetailsService(UserDetailsService userDetailsService) {
    this.userDetailsService = userDetailsService;
  }

  public ITenantedPrincipleNameResolver getUserNameUtils() {
    return userNameUtils;
  }

  public void setUserNameUtils(ITenantedPrincipleNameResolver userNameUtils) {
    this.userNameUtils = userNameUtils;
  }

  public Comparator<String> getRoleComparator() {
    return roleComparator;
  }

  public void setRoleComparator(Comparator<String> roleComparator) {
    this.roleComparator = roleComparator;
  }

  public List<String> getExtraRoles() {
    return extraRoles;
  }

  public void setExtraRoles(List<String> extraRoles) {
    this.extraRoles = extraRoles;
  }
}
