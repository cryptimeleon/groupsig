package org.cryptimeleon.groupsig.common;

import org.cryptimeleon.math.serialization.Representable;

/**
 * The issuer key used by the group manager or issuer to allow users to join the group.
 *
 * <p>It can be restored from its representation via the appropriate method from {@link GroupSignatureScheme}.
 */
public interface IssuerKey extends Representable {
}
