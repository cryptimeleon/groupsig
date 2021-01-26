package de.upb.crypto.groupsig.common;

import de.upb.crypto.math.serialization.Representable;

import java.util.Collection;

/**
 * An equality proof is similar to a {@link ClaimProof} but for multiple signatures.
 * Specifically, it proves that a specific member of the group signed a set of signatures.
 * It can be verified using {@link GroupSignatureScheme#proveEqualityVerify(EqualityProof, Collection)}.
 *
 * <p>It can be restored from its representation via the appropriate method from {@link GroupSignatureScheme}.
 *
 * @author Raphael Heitjohann
 */
public interface EqualityProof extends Representable {
}
