package org.pentaho.platform.plugin.services.security.userrole.foundry;

import org.pentaho.platform.api.engine.IUserRoleListService;
import org.pentaho.platform.api.mt.ITenant;

import java.util.List;

/**
 * Created by jchilton on 9/18/2017.
 */
public class FoundryUserRoleListService implements IUserRoleListService {
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
    return null;
  }
}
