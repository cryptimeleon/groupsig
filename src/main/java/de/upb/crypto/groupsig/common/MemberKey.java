package de.upb.crypto.groupsig.common;

import de.upb.crypto.math.serialization.Representable;

/**
 * The member key of a group member. Allows creating signatures for that group.
 *
 * <p>It can be restored from its representation via the appropriate method from {@link GroupSignatureScheme}.
 */
public interface MemberKey extends Representable {

    Integer getIdentity();
}
