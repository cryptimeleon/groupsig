package org.cryptimeleon.groupsig.common;


import org.cryptimeleon.craco.sig.Signature;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.RepresentationRestorer;

import java.lang.reflect.Type;

/**
 * A group signature created by a member of the group.
 *
 * <p>It can be restored from its representation via the appropriate method from {@link GroupSignatureScheme}.
 */
public interface GroupSignature extends Signature, RepresentationRestorer {

    ClaimProof restoreClaimProof(Representation repr);

    OpenProof restoreOpenProof(Representation repr);

    default Object restoreFromRepresentation(Type type, Representation repr) {
        if (type instanceof Class) {
            if (ClaimProof.class.isAssignableFrom((Class) type)) {
                return this.restoreClaimProof(repr);
            } else if (OpenProof.class.isAssignableFrom((Class) type)) {
                return this.restoreOpenProof(repr);
            }
        }
        throw new IllegalArgumentException("Cannot recreate object of type: " + type.getTypeName());
    }
}
