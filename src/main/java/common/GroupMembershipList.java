package common;

import de.upb.crypto.math.serialization.Representable;

/**
 * The group member ship list contains information about each group member in the form of {@link GMLEntry} instances.
 *
 * <p>It can be restored from its representation via the appropriate method from {@link GroupSignatureScheme}.
 *
 * @author Raphael Heitjohann
 */
public interface GroupMembershipList extends Representable {

    /**
     * Add an entry to the group membership list.
     *
     * @param e The {@link GMLEntry} to add
     */
    void put(GMLEntry e);

    /**
     * Retrieve the entry belonging to the given member identity from the group membership list.
     *
     * @param id An {@link Integer} representing a member identity
     * @return The {@link GMLEntry} belonging to the identity, or {@link null} if no such entry exists
     */
    GMLEntry get(Integer id);
}
