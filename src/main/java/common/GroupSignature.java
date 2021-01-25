package common;

import de.upb.crypto.craco.sig.interfaces.Signature;

/**
 * A group signature created by a member of the group.
 *
 * <p>It can be restored from its representation via the appropriate method from {@link GroupSignatureScheme}.
 *
 * @author Raphael Heitjohann
 */
public interface GroupSignature extends Signature {
}
