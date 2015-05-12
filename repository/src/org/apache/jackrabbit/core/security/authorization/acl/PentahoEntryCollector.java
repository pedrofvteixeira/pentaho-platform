/*!
 * Copyright 2010 - 2014 Pentaho Corporation.  All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.apache.jackrabbit.core.security.authorization.acl;

import org.apache.commons.lang.ArrayUtils;
import org.apache.jackrabbit.api.JackrabbitWorkspace;
import org.apache.jackrabbit.api.security.JackrabbitAccessControlManager;
import org.apache.jackrabbit.core.NodeImpl;
import org.apache.jackrabbit.core.SessionImpl;
import org.apache.jackrabbit.core.id.NodeId;
import org.apache.jackrabbit.core.security.authorization.PrivilegeBits;
import org.apache.jackrabbit.core.security.authorization.PrivilegeManagerImpl;
import org.pentaho.platform.api.engine.IAuthorizationPolicy;
import org.pentaho.platform.api.engine.IPentahoSession;
import org.pentaho.platform.api.engine.ObjectFactoryException;
import org.pentaho.platform.api.mt.ITenant;
import org.pentaho.platform.engine.core.system.PentahoSessionHolder;
import org.pentaho.platform.engine.core.system.PentahoSystem;
import org.pentaho.platform.engine.security.SecurityHelper;
import org.pentaho.platform.repository2.unified.jcr.IAclMetadataStrategy.AclMetadata;
import org.pentaho.platform.repository2.unified.jcr.JcrRepositoryFileAclUtils;
import org.pentaho.platform.repository2.unified.jcr.JcrTenantUtils;
import org.pentaho.platform.security.policy.rolebased.IRoleAuthorizationPolicyRoleBindingDao;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.Authentication;
import org.springframework.security.GrantedAuthority;
import org.springframework.util.Assert;

import javax.jcr.RepositoryException;
import javax.jcr.security.*;
import javax.jcr.version.VersionHistory;
import java.security.Principal;
import java.security.acl.Group;
import java.text.MessageFormat;
import java.util.*;

/**
 * Copy-and-paste of {@code org.apache.jackrabbit.core.security.authorization.acl.EntryCollector} in Jackrabbit 2.4.0.
 * This class is in {@code org.apache.jackrabbit.core.security.authorization.acl} package due to the scope of
 * collaborating classes.
 * <p/>
 * <p> Changes to original: </p> <ul> <li>{@code Entries} always have {@code null} {@code nextId}.</li> <li>{@code
 * collectEntries()} copied from {@code EntryCollector} uses {@code entries.getNextId()} instead of {@code
 * node.getParentId()}</li> <li>{@code filterEntries()} copied from {@code EntryCollector} as it was {@code static} and
 * {@code private}.</li> <li>No caching is done in the presence of dynamic ACEs. This may need to be revisited but due
 * to the short lifetime of the way we use Sessions, it may be acceptable.</li> <li>Understands {@code
 * AclMetadataPrincipal}.</li> <li>Adds {@code MagicPrincipal}s on the fly.</li> <li>If access decision on
 * versionStorage, then find the associated file node and use that ACL.</li>
 * <p/>
 * </ul>
 *
 * @author mlowery
 */
public class PentahoEntryCollector extends EntryCollector {

  /**
   * logger instance
   */
  private static final Logger log = LoggerFactory.getLogger( PentahoEntryCollector.class );

  private List<MagicAceDefinition> magicAceDefinitions = new ArrayList<MagicAceDefinition>();

  private static final int READ = 1; // PrivilegeRegistry.READ
  private static final int MODIFY_PROPERTIES = READ << 1; // PrivilegeRegistry.MODIFY_PROPERTIES
  private static final int ADD_CHILD_NODES = MODIFY_PROPERTIES << 1; // PrivilegeRegistry.ADD_CHILD_NODES
  private static final int REMOVE_CHILD_NODES = ADD_CHILD_NODES << 1; // PrivilegeRegistry.REMOVE_CHILD_NODES

  public PentahoEntryCollector( final SessionImpl systemSession, final NodeId rootID, final Map configuration )
    throws RepositoryException {
    super( systemSession, rootID );
    parseMagicAceDefinitions( configuration );
  }

  /**
   * Parses all magic ACE definitions.
   */
  protected void parseMagicAceDefinitions( final Map configuration ) throws RepositoryException {
    for ( int i = 0;; i++ ) {
      String value = (String) configuration.get( "magicAceDefinition" + i ); //$NON-NLS-1$
      if ( value == null ) {
        break;
      }
      MagicAceDefinition pam = parseMagicAceDefinition( value );
      magicAceDefinitions.add( pam );
    }
    if ( log.isDebugEnabled() ) {
      log.debug( "magic ACE definitions: " + magicAceDefinitions ); //$NON-NLS-1$
    }
  }

  /**
   * Parses a single magic ACE definition.
   */
  protected MagicAceDefinition parseMagicAceDefinition( final String value ) throws RepositoryException {
    String[] tokens = value.split( "\\;" ); //$NON-NLS-1$
    String path = tokens[ 0 ];
    String logicalRole = tokens[ 1 ];
    String privilegeString = tokens[ 2 ];
    boolean applyToTarget = Boolean.valueOf( tokens[ 3 ] );
    boolean applyToChildren = Boolean.valueOf( tokens[ 4 ] );
    boolean applyToAncestors = Boolean.valueOf( tokens[ 5 ] );
    String[] exceptChildren = null;
    if ( tokens.length > 6 ) {
      exceptChildren = new String[ tokens.length - 6 ];
      for ( int i = 6; i < tokens.length; i++ ) {
        exceptChildren[ i - 6 ] = tokens[ i ];
      }
    }

    String[] privilegeTokens = privilegeString.split( "\\," ); //$NON-NLS-1$
    List<Privilege> privileges = new ArrayList<Privilege>( privilegeTokens.length );
    for ( String privilegeToken : privilegeTokens ) {
      privileges.add( systemSession.getAccessControlManager().privilegeFromName( privilegeToken ) );
    }

    return new MagicAceDefinition( path, logicalRole, privileges.toArray( new Privilege[ 0 ] ), applyToTarget,
      applyToChildren, applyToAncestors, exceptChildren );
  }

  /**
   * Find the ancestor (maybe the node itself) that is access-controlled.
   */
  protected NodeImpl findAccessControlledNode( final NodeImpl node ) throws RepositoryException {
    NodeImpl currentNode = node;
    // skip all nodes that are not access-controlled; might eventually hit root which is always access-controlled
    while ( !ACLProvider.isAccessControlled( currentNode ) ) {
      currentNode = (NodeImpl) currentNode.getParent();
    }
    return currentNode;
  }

  /**
   * Find the ancestor (maybe the node itself) that is not inheriting ACEs.
   */
  protected NodeImpl findNonInheritingNode( final NodeImpl node ) throws RepositoryException {
    NodeImpl currentNode = node;
    ACLTemplate acl;
    while ( true ) {
      currentNode = findAccessControlledNode( currentNode );
      NodeImpl aclNode = currentNode.getNode( N_POLICY ); 
      String path = aclNode != null ? aclNode.getParent().getPath() : null;
      acl = new ACLTemplate( aclNode, path, false /* allowUnknownPrincipals */ );

      // skip all nodes that are inheriting
      AclMetadata aclMetadata = JcrRepositoryFileAclUtils.getAclMetadata( systemSession, currentNode.getPath(), acl );
      if ( aclMetadata != null && aclMetadata.isEntriesInheriting() ) {
        currentNode = (NodeImpl) currentNode.getParent();
        continue;
      }
      break;
    }
    return currentNode;
  }

  /**
   * Returns an {@code Entries} for the given node. This is where most of the customization lives.
   */
  @Override
  protected Entries getEntries( final NodeImpl node ) throws RepositoryException {
    // find nearest node with an ACL that is not inheriting ACEs
    NodeImpl currentNode = node;
    ACLTemplate acl;

    // version history governed by ACL on "versionable" which could be the root if no version history exists for
    // file;
    // if we do hit the root, then you get jcr:read for everyone which is acceptable
    if ( currentNode.getPath().startsWith( "/jcr:system/jcr:versionStorage" ) ) { //$NON-NLS-1$
      currentNode = getVersionable( currentNode );
    }

    // find first access-controlled node
    currentNode = findAccessControlledNode( currentNode );
    NodeImpl aclNode = currentNode.getNode( N_POLICY ); 
    String path = aclNode != null ? aclNode.getParent().getPath() : null;
    acl = new ACLTemplate( aclNode, path, false /* allowUnknownPrincipals */ );

    // owner comes from the first access-controlled node
    String owner = null;
    AclMetadata aclMetadata = JcrRepositoryFileAclUtils.getAclMetadata( systemSession, currentNode.getPath(), acl );
    if ( aclMetadata != null ) {
      owner = aclMetadata.getOwner();
    }

    // find the ACL
    NodeImpl firstAccessControlledNode = currentNode;
    currentNode = findNonInheritingNode( currentNode );
    NodeImpl aclCurrentNode = currentNode.getNode( N_POLICY );
    String currentPath = aclCurrentNode != null ? aclCurrentNode.getParent().getPath() : null;
    acl = new ACLTemplate( aclCurrentNode, currentPath, false /* allowUnknownPrincipals */ );

    // If we're inheriting from another node, check to see if that node has removeChildNodes or addChildNodes
    // permissions. This needs to transform to become addChild removeChild
    if ( !currentNode.isSame( node ) ) {
      Privilege removeNodePrivilege =
          systemSession.getAccessControlManager().privilegeFromName( Privilege.JCR_REMOVE_NODE );

      Privilege removeChildNodesPrivilege =
          systemSession.getAccessControlManager().privilegeFromName( Privilege.JCR_REMOVE_CHILD_NODES );

      for ( AccessControlEntry entry : acl.getEntries() ) {

        Privilege[] expandedPrivileges = JcrRepositoryFileAclUtils.expandPrivileges( entry.getPrivileges(), false );
        if ( ArrayUtils.contains( expandedPrivileges, removeChildNodesPrivilege )
            && !ArrayUtils.contains( expandedPrivileges, removeNodePrivilege ) ) {
          if ( !acl.addAccessControlEntry( entry.getPrincipal(), new Privilege[] { removeNodePrivilege } ) ) {
            // we can never fail to add this entry because it means we may be giving more permission than the above
            // two
            throw new RuntimeException();
          }
          break;
        }
      }
    }

    // find first ancestor that is not inheriting; its ACEs will be used if the ACL is not inheriting
    ACLTemplate ancestorAcl = null;
    NodeImpl aclAncestorNode = null;
    String ancestorPath = null;
    if ( firstAccessControlledNode.isSame( currentNode ) && !rootID.equals( currentNode.getNodeId() ) ) {
      NodeImpl ancestorNode = findNonInheritingNode( (NodeImpl) currentNode.getParent() );
      aclAncestorNode = ancestorNode.getNode( N_POLICY );
      ancestorPath = aclAncestorNode != null ? aclAncestorNode.getParent().getPath() : null;
      ancestorAcl = new ACLTemplate( aclAncestorNode, ancestorPath, false /* allowUnknownPrincipals */ );
    }

    // now acl points to the nearest ancestor that is access-controlled and is not inheriting;
    // ancestorAcl points to first ancestor of ACL that is access-controlled and is not inheriting--possibly null
    // owner is an owner string--possibly null


     return new Entries( new ArrayList<Entry>( getAcesIncludingMagicAces( currentNode.getPath(), owner,
      ancestorAcl, acl ) ) , null );


    /*
    return new PentahoEntries( new ArrayList<AccessControlEntry>( getAcesIncludingMagicAces( currentNode.getPath(), owner,
        ancestorAcl, acl ) ) );
    */
  }

  /**
   * Incoming node is in versionStorage. Find its associated versionable--the node associated with this version history
   * node.
   */
  protected NodeImpl getVersionable( final NodeImpl node ) throws RepositoryException {
    NodeImpl currentNode = node;
    while ( !currentNode.isNodeType( "nt:versionHistory" ) && !rootID
      .equals( currentNode.getNodeId() ) ) { //$NON-NLS-1$
      currentNode = (NodeImpl) currentNode.getParent();
    }
    if ( rootID.equals( currentNode.getNodeId() ) ) {
      return currentNode;
    } else {
      return (NodeImpl) systemSession.getNodeByIdentifier( ( (VersionHistory) currentNode )
        .getVersionableIdentifier() );
    }
  }

  /**
   * {@link IAuthorizationPolicy} is used in magic ACE definitions.
   */
  protected IAuthorizationPolicy getAuthorizationPolicy() {
    IAuthorizationPolicy authorizationPolicy = PentahoSystem.get( IAuthorizationPolicy.class );
    if ( authorizationPolicy == null ) {
      throw new IllegalStateException();
    }
    return authorizationPolicy;
  }

  protected IRoleAuthorizationPolicyRoleBindingDao getRoleBindingDao() {
    return PentahoSystem.get( IRoleAuthorizationPolicyRoleBindingDao.class );
  }

  /**
   * Extracts ACEs including magic aces. Magic ACEs are added for (1) the owner, (2) as a result of magic ACE
   * definitions, and (3) as a result of ancestor ACL contributions.
   * <p/>
   * <p> Modifications to these ACLs are not persisted. </p>
   */
  protected List<Entry> getAcesIncludingMagicAces( final String path, final String owner,
                                                                final ACLTemplate ancestorAcl, final ACLTemplate acl )
    throws RepositoryException {
    if ( PentahoSessionHolder.getSession() == null || PentahoSessionHolder.getSession().getId() == null
        || PentahoSessionHolder.getSession().getId().trim().equals( "" ) ) { //$NON-NLS-1$
      if ( log.isDebugEnabled() ) {
        log.debug( "no PentahoSession so no magic ACEs" ); //$NON-NLS-1$
      }
      return Collections.emptyList();
    }
    if ( owner != null ) {
      addOwnerAce( owner, acl );
    }

    boolean match = false;
    IRoleAuthorizationPolicyRoleBindingDao roleBindingDao = null;
    try {
      roleBindingDao =
        PentahoSystem.getObjectFactory().get( IRoleAuthorizationPolicyRoleBindingDao.class,
          "roleAuthorizationPolicyRoleBindingDaoTarget", PentahoSessionHolder.getSession() );
    } catch ( ObjectFactoryException e ) {
      e.printStackTrace();
    }

    ITenant tenant = JcrTenantUtils.getTenant();
    for ( final MagicAceDefinition def : magicAceDefinitions ) {
      match = false;

      String substitutedPath = MessageFormat.format( def.path, tenant.getRootFolderAbsolutePath() );
      if ( isAllowed( roleBindingDao, def.logicalRole ) ) {
        if ( def.applyToTarget ) {
          match = path.equals( substitutedPath );
        }
        if ( !match && def.applyToChildren ) {
          match = path.startsWith( substitutedPath + "/" );
          // check to see if we should exclude the match due to the exclude list
          if ( match && def.exceptChildren != null ) {
            for ( String childPath : def.exceptChildren ) {
              String substitutedChildPath = MessageFormat.format( childPath, tenant.getRootFolderAbsolutePath() );
              if ( path.startsWith( substitutedChildPath + "/" ) ) {
                match = false;
                break;
              }
            }
          }
        }
        if ( !match && def.applyToAncestors ) {
          match = substitutedPath.startsWith( path + "/" );
        }
      }
      if ( match ) {
        Principal principal =
            new MagicPrincipal( JcrTenantUtils.getTenantedUser( PentahoSessionHolder.getSession().getName() ) );
        // unfortunately, we need the ACLTemplate because it alone can create ACEs that can be cast successfully
        // later;
        // changed never persisted
        acl.addAccessControlEntry( principal, def.privileges );
      }
    }


    List<Entry> acEntries = new ArrayList<Entry>();
    acEntries.addAll( readEntries( acl ) ); // leaf ACEs go first so ACL metadata ACE stays first
    acEntries.addAll( getRelevantAncestorAces( ancestorAcl ) );
    return acEntries;


    /*
    List<AccessControlEntry> acEntries = new ArrayList<AccessControlEntry>();
    acEntries.addAll( acl.getEntries() ); // leaf ACEs go first so ACL metadata ACE stays first
    acEntries.addAll( getRelevantAncestorAces( ancestorAcl ) );
    return acEntries;
    */
  }

  /**
   * Selects (and modifies) ACEs containing JCR_ADD_CHILD_NODES or JCR_REMOVE_CHILD_NODES privileges from the given
   * ACL.
   * <p/>
   * <p> Modifications to this ACL are not persisted. ACEs must be created in the given ACL because the path embedded in
   * the given ACL plays into authorization decisions using parentPrivs. </p>
   */
  protected List<Entry> getRelevantAncestorAces( final ACLTemplate ancestorAcl )
    throws RepositoryException {

    if ( ancestorAcl == null ) {
      return Collections.emptyList();
    }

    NodeImpl ancestorNode = (NodeImpl) systemSession.getNode( ancestorAcl.getPath() );
    Entries fullEntriesIncludingMagicACEs = this.getEntries( ancestorNode );

    JackrabbitAccessControlManager acMgr = ( JackrabbitAccessControlManager ) systemSession.getAccessControlManager();
    PrivilegeManagerImpl privMrg =
        ( PrivilegeManagerImpl ) ( (( JackrabbitWorkspace ) systemSession.getWorkspace() ).getPrivilegeManager() );

    Privilege addChildNodesPrivilege = acMgr.privilegeFromName( Privilege.JCR_ADD_CHILD_NODES );
    PrivilegeBits addChildNodesPrivilegeBits = privMrg.getBits( addChildNodesPrivilege );

    Privilege removeChildNodesPrivilege = acMgr.privilegeFromName( Privilege.JCR_REMOVE_CHILD_NODES );
    PrivilegeBits removeChildNodesPrivilegeBits = privMrg.getBits( removeChildNodesPrivilege );

    for ( Entry entry : fullEntriesIncludingMagicACEs.getACEs() ) {

      List<Privilege> privs = new ArrayList<Privilege>( 2 );

      if ( entry.getPrivilegeBits().includes( addChildNodesPrivilegeBits ) ) {
        privs.add( addChildNodesPrivilege );
      }
      if ( entry.getPrivilegeBits().includes( removeChildNodesPrivilegeBits ) ) {
        privs.add( removeChildNodesPrivilege );
      }
      // remove all physical entries from the ACL. MagicAces will not be present in the ACL Entries, so we check
      // before trying to remove
      if ( ancestorAcl.getEntries().contains( entry ) ) {
        // ancestorAcl.removeAccessControlEntry( entry ); TODO CHECK
      }
      // remove existing ACE since (1) it doesn't have the privs we're looking for and (2) the following
      // addAccessControlEntry will silently fail to add a new ACE if perms already exist
      if ( !privs.isEmpty() ) {
        // create new ACE with same principal but only privs relevant to child operations
        // clone to new list to allow concurrent modification
        List<AccessControlEntry> entries = new LinkedList<AccessControlEntry>( ancestorAcl.getEntries() );
        for ( AccessControlEntry accessControlEntry : entries ) {

          if ( accessControlEntry.getPrincipal().getName().equals( entry.getPrincipalName() ) ) {
            ancestorAcl.removeAccessControlEntry( accessControlEntry );
        }
      }

      if ( !ancestorAcl.addAccessControlEntry( entry.isGroupEntry() ?
              new MagicGroup( entry.getPrincipalName() ) : new MagicPrincipal( entry.getPrincipalName() ),
          privs.toArray( new Privilege[ privs.size() ] ) ) ) {
          // we can never fail to add this entry because it means we may be giving more permission than the above two
          throw new RuntimeException();
        }
      }
    }

    return readEntries( ancestorAcl );

    /*

    for ( AccessControlEntry entry : fullEntriesIncludingMagicACEs.getAccessControlEntries() ) {
      List<Privilege> privs = new ArrayList<Privilege>( 2 );
      Privilege[] expandedPrivileges = JcrRepositoryFileAclUtils.expandPrivileges( entry.getPrivileges(), false );
      if ( ArrayUtils.contains( expandedPrivileges, addChildNodesPrivilege ) ) {
        privs.add( addChildNodesPrivilege );
      }
      if ( ArrayUtils.contains( expandedPrivileges, removeChildNodesPrivilege ) ) {
        privs.add( removeChildNodesPrivilege );
      }
      // remove all physical entries from the ACL. MagicAces will not be present in the ACL Entries, so we check
      // before
      // trying to remove
      if ( ancestorAcl.getEntries().contains( entry ) ) {
        ancestorAcl.removeAccessControlEntry( entry );
      }
      // remove existing ACE since (1) it doesn't have the privs we're looking for and (2) the following
      // addAccessControlEntry will silently fail to add a new ACE if perms already exist
      if ( !privs.isEmpty() ) {
        // create new ACE with same principal but only privs relevant to child operations
        // clone to new list to allow concurrent modification
        List<AccessControlEntry> entries = new LinkedList<AccessControlEntry>( ancestorAcl.getEntries() );
        for ( AccessControlEntry accessControlEntry : entries ) {
          if ( accessControlEntry.getPrincipal().getName().equals( entry.getPrincipal().getName() ) ) {
            ancestorAcl.removeAccessControlEntry( accessControlEntry );
          }
        }
        if ( !ancestorAcl.addAccessControlEntry( entry.getPrincipal() instanceof Group ? new MagicGroup( entry
            .getPrincipal().getName() ) : new MagicPrincipal( entry.getPrincipal().getName() ), privs
            .toArray( new Privilege[ privs.size() ] ) ) ) {
          // we can never fail to add this entry because it means we may be giving more permission than the above
          // two
          throw new RuntimeException();
        }
      }
    }
    return ancestorAcl.getEntries();

    */
  }

  /**
   * Creates an ACE that gives full access to the owner.
   * <p/>
   * <p> Modifications to this ACL are not persisted. </p>
   */
  protected void addOwnerAce( final String owner, final ACLTemplate acl ) throws RepositoryException {
    Principal ownerPrincipal = systemSession.getPrincipalManager().getPrincipal( owner );
    if ( ownerPrincipal != null ) {
      Principal magicPrincipal = null;
      if ( ownerPrincipal instanceof Group ) {
        magicPrincipal = new MagicGroup( JcrTenantUtils.getTenantedUser( ownerPrincipal.getName() ) );
      } else {
        magicPrincipal = new MagicPrincipal( JcrTenantUtils.getTenantedUser( ownerPrincipal.getName() ) );
      }
      // unfortunately, we need the ACLTemplate because it alone can create ACEs that can be cast successfully
      // later;
      // changed never persisted
      acl.addAccessControlEntry( magicPrincipal, new Privilege[] { systemSession.getAccessControlManager()
          .privilegeFromName( "jcr:all" ) } ); //$NON-NLS-1$
    } else {
      // if the Principal doesn't exist anymore, then there's no reason to add an ACE for it
      if ( log.isDebugEnabled() ) {
        log.debug( "PrincipalManager cannot find owner=" + owner ); //$NON-NLS-1$
      }
    }

  }

  /**
   * Overridden since {@code collectEntries()} from {@code EntryCollector} called {@code node.getParentId()} instead of
   * {@code entries.getNextId()}.
   */
  @Override
  protected List<Entry> collectEntries( NodeImpl node, EntryFilter filter ) throws RepositoryException {
    LinkedList<Entry> userAces = new LinkedList<Entry>();
    LinkedList<Entry> groupAces = new LinkedList<Entry>();

    if ( node == null ) {
      // repository level permissions
      NodeImpl root = (NodeImpl) systemSession.getRootNode();
      if ( ACLProvider.isRepoAccessControlled( root ) ) {
        NodeImpl aclNode = root.getNode( N_REPO_POLICY );
        String path = aclNode != null ? aclNode.getParent().getPath() : null;
        filterEntries( filter, Entry.readEntries( aclNode, path ), userAces, groupAces );
      }
    } else {
      Entries entries = getEntries( node );
      filterEntries( filter, entries.getACEs(), userAces, groupAces );
      NodeId next = entries.getNextId();
      while ( next != null ) {
        entries = getEntries( next );
        filterEntries( filter, entries.getACEs(), userAces, groupAces );
        next = entries.getNextId();
      }
    }

    List<Entry> entries = new ArrayList<Entry>( userAces.size() + groupAces.size() );
    entries.addAll( userAces );
    entries.addAll( groupAces );

    return entries;
  }

  /**
   * Copied from {@link EntryCollector} since that method was {@code private}.
   */
  @SuppressWarnings( "unchecked" )
  protected void filterEntries( EntryFilter filter, List<Entry> aces,
                                LinkedList<Entry> userAces, LinkedList<Entry> groupAces ) {
    if ( !aces.isEmpty() && filter != null ) {
      filter.filterEntries( aces, userAces, groupAces );
    }
  }

  protected void filterEntriesLegacy( EntryFilter filter, List<AccessControlEntry> aces,
      LinkedList<AccessControlEntry> userAces, LinkedList<AccessControlEntry> groupAces ) {
    if ( !aces.isEmpty() && filter != null ) {
      //filter.filterEntries( aces, userAces, groupAces );
    }
  }

  protected List<String> getRuntimeRoleNames() {
    IPentahoSession pentahoSession = PentahoSessionHolder.getSession();
    List<String> runtimeRoles = new ArrayList<String>();
    Assert.state( pentahoSession != null );
    Authentication authentication = SecurityHelper.getInstance().getAuthentication();
    if ( authentication != null ) {
      GrantedAuthority[] authorities = authentication.getAuthorities();
      for ( int i = 0; i < authorities.length; i++ ) {
        runtimeRoles.add( authorities[ i ].getAuthority() );
      }
    }
    return runtimeRoles;
  }

  protected boolean isAllowed( IRoleAuthorizationPolicyRoleBindingDao roleBindingDao, String logicalRoleName )
    throws RepositoryException {
    return roleBindingDao.getBoundLogicalRoleNames( systemSession, getRuntimeRoleNames() ).contains(
        logicalRoleName );
  }

  private static AccessControlList getACList(AccessControlManager acMgr, String path) throws RepositoryException {

    for ( AccessControlPolicyIterator it = acMgr.getApplicablePolicies(path); it.hasNext(); ) {
      AccessControlPolicy acp = it.nextAccessControlPolicy();
      if ( acp instanceof AccessControlList ) {
        return ( AccessControlList ) acp;
      }
    }
    AccessControlPolicy[] acps = acMgr.getPolicies(path);
    for (int i = 0; i < acps.length; i++) {
      if ( acps[i] instanceof AccessControlList ) {
        return (AccessControlList) acps[i] ;
      }
    }
    return null;
  }

  private List<Entry> readEntries( ACLTemplate acl ) throws RepositoryException {
    if( acl != null ){
      NodeImpl aclNode = (NodeImpl) systemSession.getNode( acl.getPath() );
      return Entry.readEntries( aclNode.getNode( N_POLICY ), acl.getPath() );
    }
    return new ArrayList<Entry>();
  }

  static class PentahoEntries extends Entries {

    private List<AccessControlEntry> accessControlEntries = new ArrayList<AccessControlEntry>();

    PentahoEntries( List<Entry> aces, NodeId nextId ) {
      super( aces, nextId );
    }

    PentahoEntries( Entries e ) {
      super( e.getACEs(), e.getNextId() );
    }

    PentahoEntries( List<AccessControlEntry> accessControlEntries ) {
      super( null, null );
      this.accessControlEntries = accessControlEntries;
    }

    public List<AccessControlEntry> getAccessControlEntries() {
      return accessControlEntries;
    }

    public void addAccessControlEntry( AccessControlEntry ace ) {
      getAccessControlEntries().add( ace );
    }
  }
}
