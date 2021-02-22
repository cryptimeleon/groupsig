package org.cryptimeleon.groupsig.common;


import org.cryptimeleon.craco.sig.Signature;

/**
 * A group signature created by a member of the group.
 *
 * <p>It can be restored from its representation via the appropriate method from {@link GroupSignatureScheme}.
 */
public interface GroupSignature extends Signature {
}
