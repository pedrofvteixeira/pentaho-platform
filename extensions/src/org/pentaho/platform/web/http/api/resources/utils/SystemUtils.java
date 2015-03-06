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
 * Copyright (c) 2002-2014 Pentaho Corporation..  All rights reserved.
 */

package org.pentaho.platform.web.http.api.resources.utils;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.pentaho.platform.api.engine.IAuthorizationAction;
import org.pentaho.platform.api.engine.IAuthorizationPolicy;
import org.pentaho.platform.api.engine.IPentahoSession;
import org.pentaho.platform.api.engine.ISecurityHelper;
import org.pentaho.platform.engine.core.system.PentahoSystem;
import org.pentaho.platform.security.policy.rolebased.actions.AdministerSecurityAction;
import org.pentaho.platform.security.policy.rolebased.actions.RepositoryCreateAction;
import org.pentaho.platform.security.policy.rolebased.actions.RepositoryReadAction;

import java.util.concurrent.Callable;

public class SystemUtils {

  private static final Log logger = LogFactory.getLog( SystemUtils.class );

  /**
   * Utility method that communicates with the implemented IAuthorizationPolicy to determine administrator status
   *
   * @return true if the user is considered a Pentaho administrator
   */
  public static boolean canAdminister() {
    return canAdminister( getPolicy() );
  }

  /**
   * Utility method that communicates with the provided IAuthorizationPolicy to determine administrator status
   *
   * @param policy The IAuthorizationPolicy object
   * @return true if the user is considered a Pentaho administrator
   */
  public static boolean canAdminister( IAuthorizationPolicy policy ) {

    return policy.isAllowed( RepositoryReadAction.NAME ) && policy.isAllowed( RepositoryCreateAction.NAME )
        && ( policy.isAllowed( AdministerSecurityAction.NAME ) );
  }

  /**
   * Utility method that communicates with the implemented IAuthorizationPolicy to determine if the provided action
   * is allowed
   *
   * @param action The IAuthorizationAction object
   * @return true if the user is considered a Pentaho administrator
   */
  public static boolean isAllowed( IAuthorizationAction action ) {
    return isAllowed( getPolicy(), action );
  }


  /**
   * Utility method that communicates with the implemented IAuthorizationPolicy to determine administrator status
   *
   * @return true if the user is considered a Pentaho administrator
   */
  public static boolean isAllowed( IAuthorizationPolicy policy, IAuthorizationAction action ) {
    return policy.isAllowed( action.getName() );
  }


  /**
   * Utility method that communicates with the implemented IAuthorizationPolicy to determine administrator status
   *
   * @param user The IPentahoSession user
   * @return true if the user is considered a Pentaho administrator
   */
  public static boolean canAdminister( final IPentahoSession user ) {
    return canAdminister( user, getPolicy() );
  }

  /**
   * Utility method that communicates with the implemented IAuthorizationPolicy to determine administrator status
   *
   * @param user The IPentahoSession user
   * @param policy The IAuthorizationPolicy object
   * @return true if the user is considered a Pentaho administrator
   */
  public static boolean canAdminister( final IPentahoSession user, final IAuthorizationPolicy policy ) {

    if( user == null ){
      return canAdminister();
    }

    ISecurityHelper security = PentahoSystem.get( ISecurityHelper.class );

    try {

      return security.runAsUser( user.getName() , null, new Callable<Boolean>() {
        @Override
        public Boolean call() throws Exception {
          return SystemUtils.canAdminister( policy );
        }
      });

    } catch ( Exception e ) {
      getLogger().error( e.getLocalizedMessage(), e );
    }
    return false;
  }

  protected static IAuthorizationPolicy getPolicy() {
    return PentahoSystem.get( IAuthorizationPolicy.class );
  }

  protected static Log getLogger() {
    return logger;
  }
}
