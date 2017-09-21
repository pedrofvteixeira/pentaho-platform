package org.pentaho.platform.plugin.services.security.userrole.foundry;

import org.pentaho.platform.api.engine.IUserRoleListService;
import org.pentaho.platform.api.mt.ITenant;
import org.pentaho.platform.api.mt.ITenantedPrincipleNameResolver;
import org.pentaho.platform.repository2.unified.jcr.JcrTenantUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserCache;
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

    /* Foundry does not provide the means to fetch Roles for a particular user.
     * Therefore, this method can not do much more that simply assigning the user with whatever
     * are the 'extraRoles' being set in applicationContext-spring-security */

    if ( tenant != null && !tenant.equals( JcrTenantUtils.getDefaultTenant() ) ) {
      throw new UnsupportedOperationException( "only allowed to access to default tenant" );
    }

    UserDetails user = getUserDetailsService().loadUserByUsername( getUserNameUtils().getPrincipleName( username ) );
    Collection<? extends GrantedAuthority> results = user.getAuthorities();
    Set<String> roles = ( getRoleComparator() != null ) ? new TreeSet<String>( getRoleComparator() ) : new LinkedHashSet<String>( results.size() );
    for ( GrantedAuthority role : results ) {
      roles.add( role.getAuthority() );
    }

    // Now add extra role if it does not exist in the list
    for ( String extraRole : getExtraRoles() ) {
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
