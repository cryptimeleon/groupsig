package org.cryptimeleon.groupsig.cpy06;

import org.cryptimeleon.craco.protocols.arguments.fiatshamir.FiatShamirProof;
import org.cryptimeleon.craco.protocols.arguments.fiatshamir.FiatShamirProofSystem;
import org.cryptimeleon.groupsig.common.ClaimProof;
import org.cryptimeleon.groupsig.cpy06.claimpok.CPY06ClaimFSProof;
import org.cryptimeleon.math.serialization.ObjectRepresentation;
import org.cryptimeleon.math.serialization.Representation;

import java.util.Objects;

public class CPY06ClaimProof implements ClaimProof {

    private final FiatShamirProof proof;

    public CPY06ClaimProof(FiatShamirProof proof) {
        this.proof = proof;
    }

    public CPY06ClaimProof(Representation repr, CPY06PublicParameters pp, CPY06Signature signature) {
        ObjectRepresentation representation = (ObjectRepresentation) repr;
        FiatShamirProofSystem proofSystem = new FiatShamirProofSystem(new CPY06ClaimFSProof(pp));
        this.proof = proofSystem.restoreProof(signature, representation.get("proof"));
    }

    public FiatShamirProof getProof() {
        return proof;
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation repr = new ObjectRepresentation();
        repr.put("proof", proof.getRepresentation());
        return repr;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CPY06ClaimProof that = (CPY06ClaimProof) o;
        return Objects.equals(proof, that.proof);
    }

    @Override
    public int hashCode() {
        return Objects.hash(proof);
    }
}
