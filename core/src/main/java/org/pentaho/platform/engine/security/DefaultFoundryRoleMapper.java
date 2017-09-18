package org.pentaho.platform.engine.security;

import org.pentaho.platform.api.engine.security.IAuthenticationRoleMapper;

/**
 * Created by jchilton on 9/18/2017.
 */
public class DefaultFoundryRoleMapper implements IAuthenticationRoleMapper {
  @Override
  public String toPentahoRole(String thirdPartyRole) {
    return null;
  }

  @Override
  public String fromPentahoRole(String pentahoRole) {
    return null;
  }
}
