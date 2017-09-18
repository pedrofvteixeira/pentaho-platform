package org.pentaho.platform.plugin.services.security.userrole.foundry;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.authentication.AuthenticationProvider;
/**
 * Created by jchilton on 9/18/2017.
 */
public class FoundryAuthenticationProvider implements AuthenticationProvider {
  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    return null;
  }

  @Override
  public boolean supports(Class<?> aClass) {
    return false;
  }
}
