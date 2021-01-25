package common;

import de.upb.crypto.math.serialization.Representable;

/**
 * A group membership list entry contains information about a specific member of the group.
 * It is created during the joining process for that specific member and added to the {@link GroupMembershipList}.
 *
 * <p>It can be restored from its representation via the appropriate method from {@link GroupSignatureScheme}.
 *
 * @author Raphael Heitjohann
 */
public interface GMLEntry extends Representable {
}
