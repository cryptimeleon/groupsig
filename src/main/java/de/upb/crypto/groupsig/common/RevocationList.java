package de.upb.crypto.groupsig.common;

import de.upb.crypto.math.serialization.Representable;

/**
 * Contains information about former group members that had their membership status revoked in the form of
 * {@link RevocationListEntry} instances.
 *
 * <p>It can be restored from its representation via the appropriate method from {@link GroupSignatureScheme}.
 *
 * @author Raphael Heitjohann
 */
public interface RevocationList extends Representable {

    /**
     * Add an entry to the revocation list.
     *
     * @param e The {@link RevocationListEntry} to add
     */
    void put(RevocationListEntry e);

    /**
     * Retrieve the entry belonging to the given member identity from the revocation list.
     *
     * @param id An {@link Integer} representing a member identity
     * @return The {@link RevocationListEntry} belonging to the identity, or {@link null} if no such entry exists
     */
    RevocationListEntry get(Integer id);
}
