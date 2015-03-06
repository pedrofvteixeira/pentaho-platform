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
 * Copyright (c) 2002-2013 Pentaho Corporation..  All rights reserved.
 */

package org.pentaho.platform.plugin.services.metadata;

import org.pentaho.metadata.model.concept.Concept;
import org.pentaho.metadata.model.concept.IConcept;
import org.pentaho.metadata.model.concept.security.Security;
import org.pentaho.metadata.model.concept.security.SecurityOwner;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class PentahoMetadataAclHolder /* implements IAclHolder TODO */ {

  private List /* <IPentahoAclEntry> TODO */ accessControls = new ArrayList /* <IPentahoAclEntry> TODO */ ();

  public PentahoMetadataAclHolder( final IConcept aclHolder ) {
    try {
      Security sec = (Security) aclHolder.getProperty( Concept.SECURITY_PROPERTY );
      if ( sec != null ) {
        Map<SecurityOwner, Integer> securityMap = sec.getOwnerAclMap();
        SecurityOwner secOwn = null;
        for ( Map.Entry<SecurityOwner, Integer> entry : securityMap.entrySet() ) {
          // We now have the SecurityOwner and the Rights in there.
          secOwn = entry.getKey();
          int rights = entry.getValue().intValue();
          if ( secOwn.getOwnerType() == SecurityOwner.OwnerType.USER ) {
            /* accessControls.add( new PentahoAclEntry( secOwn.getOwnerName(), rights ) ) TODO */;
          } else {
            /* accessControls.add( new PentahoAclEntry( new GrantedAuthorityImpl( secOwn.getOwnerName() ), rights ) ) TODO */;
          }
        }
      }
    } catch ( Throwable th ) {
      // Just being paranoid here in case something doesn't support it.
    }

  }

  public List /* <IPentahoAclEntry> TODO */ getAccessControls() {
    return accessControls;
  }

  public List /* <IPentahoAclEntry> TODO */ getEffectiveAccessControls() {
    return accessControls;
  }

  public void resetAccessControls( final List /* <IPentahoAclEntry> TODO */ acls ) {
    throw new UnsupportedOperationException( "Cannot set Metadata Acls yet" ); //$NON-NLS-1$
  }

  public void setAccessControls( final List /* <IPentahoAclEntry> TODO */ acls ) {
    throw new UnsupportedOperationException( "Cannot set Metadata Acls yet" ); //$NON-NLS-1$
  }

}
