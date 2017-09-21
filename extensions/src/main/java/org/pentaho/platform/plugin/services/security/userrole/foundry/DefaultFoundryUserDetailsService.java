package org.pentaho.platform.plugin.services.security.userrole.foundry;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * Created by jchilton on 9/18/2017.
 */
public class DefaultFoundryUserDetailsService  implements UserDetailsService {

  @Override
  public UserDetails loadUserByUsername( String username ) throws UsernameNotFoundException {
    return null; /* no-op */
  }

}
