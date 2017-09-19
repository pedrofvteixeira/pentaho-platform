package org.pentaho.platform.plugin.services.security.userrole.foundry;

import org.apache.commons.lang.StringUtils;
import org.pentaho.platform.repository2.unified.jcr.JcrTenantUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Map;

/**
 * Created by jchilton on 9/18/2017.
 */
public class DefaultFoundryUserDetailsService  implements UserDetailsService {

  private Map<String, UserDetails> userMap;

  public DefaultFoundryUserDetailsService( Map<String, UserDetails> userMap ) {
    setUserMap( userMap );
  }

  @Override
  public UserDetails loadUserByUsername( String user ) throws UsernameNotFoundException {

    if( !StringUtils.isEmpty( user ) && getUserMap().containsKey(JcrTenantUtils.getPrincipalName( user, true ) ) ) {
      return getUserMap().get( user );
    }

    throw new UsernameNotFoundException( null );
  }

  public Map<String, UserDetails> getUserMap() {
    return userMap;
  }

  public void setUserMap(Map<String, UserDetails> userMap) {
    this.userMap = userMap;
  }
}
