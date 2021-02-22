package org.cryptimeleon.groupsig.common;

import org.cryptimeleon.math.serialization.Representable;

/**
 * The opener key used by the group manager or opener to open signatures and obtain tracing trapdoors.
 *
 * <p>It can be restored from its representation via the appropriate method from {@link GroupSignatureScheme}.
 */
public interface OpenerKey extends Representable {
}
