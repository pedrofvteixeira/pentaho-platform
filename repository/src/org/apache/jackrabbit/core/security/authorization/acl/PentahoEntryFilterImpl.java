package org.apache.jackrabbit.core.security.authorization.acl;

import org.apache.jackrabbit.core.SessionImpl;
import org.apache.jackrabbit.core.id.ItemId;
import org.apache.jackrabbit.spi.Path;
import org.apache.jackrabbit.spi.commons.conversion.PathResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jcr.security.AccessControlEntry;
import java.security.acl.Group;
import java.util.Collection;
import java.util.List;

public class PentahoEntryFilterImpl extends EntryFilterImpl {

  private static final Logger log = LoggerFactory.getLogger( PentahoEntryFilterImpl.class );

  private final Collection<String> principalNames;

  PentahoEntryFilterImpl( Collection<String> principalNames, ItemId id, SessionImpl sessionImpl ) {
    super( principalNames, id, sessionImpl );
    this.principalNames = principalNames;
  }

  PentahoEntryFilterImpl( Collection<String> principalNames, Path absPath, PathResolver pathResolver ) {
    super( principalNames, absPath, pathResolver );
    this.principalNames = principalNames;
  }

  /**
   * Separately collect the entries defined for the user and group
   * principals.
   *
   * @param entries
   * @param resultLists
   * @see EntryFilter#filterEntries(java.util.List, java.util.List[])
   */
  public void filterEntriesLegacy(List<AccessControlEntry> entries, List<AccessControlEntry>... resultLists) {
    if (resultLists.length == 2) {
      List<AccessControlEntry> userAces = resultLists[0];
      List<AccessControlEntry> groupAces = resultLists[1];

      int uInsertIndex = userAces.size();
      int gInsertIndex = groupAces.size();

      // first collect aces present on the given aclNode.
      for (AccessControlEntry ace : entries) {
        // only process ace if 'principalName' is contained in the given set
        if (matches(ace)) {
          // add it to the proper list (e.g. separated by principals)
          /**
           * NOTE: access control entries must be collected in reverse
           * order in order to assert proper evaluation.
           */
          if (ace.getPrincipal() instanceof Group ) {
            groupAces.add(gInsertIndex, ace);
          } else {
            userAces.add(uInsertIndex, ace);
          }
        }
      }
    } else {
      log.warn("Filtering aborted. Expected 2 result lists.");
    }
  }

  private boolean matches( AccessControlEntry ace ) {
    if (principalNames == null || principalNames.contains(ace.getPrincipal().getName())) {
      ACLTemplate.Entry entry = (ACLTemplate.Entry) ace;
      if (!entry.hasRestrictions()) {
        // short cut: there is no glob-restriction -> the entry matches
        // because it is either defined on the node or inherited.
        return true;
      } else {
        // there is a glob-restriction: check if the target path matches
        // this entry.

        // TODO CHECK
        /*
        try {
          return entry.matches( getPath() ); ;
        } catch (RepositoryException e) {
          log.error("Cannot determine ACE match.", e);
        }
        */
      }
    }

    // doesn't match this filter -> ignore
    return false;
  }



}
