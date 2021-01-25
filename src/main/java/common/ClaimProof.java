package common;

import de.upb.crypto.math.serialization.Representable;

/**
 * A claim proof proves that a {@link GroupSignature} was issued by specific member of
 * the group. It can be verified using {@link GroupSignatureScheme#claimVerify(ClaimProof, GroupSignature)}.
 *
 * <p>It can be restored from its representation via the appropriate method from {@link GroupSignatureScheme}.
 *
 * @author Raphael Heitjohann
 */
public interface ClaimProof extends Representable {
}
