package org.cryptimeleon.groupsig.cpy06.issuingprotocol;

import org.cryptimeleon.craco.protocols.arguments.fiatshamir.FiatShamirProof;
import org.cryptimeleon.craco.protocols.arguments.fiatshamir.FiatShamirProofSystem;
import org.cryptimeleon.groupsig.cpy06.CPY06PublicParameters;
import org.cryptimeleon.groupsig.cpy06.issuingprotocol.joinpok.CPY06XiProof;
import org.cryptimeleon.groupsig.cpy06.issuingprotocol.joinpok.CPY06XiProofCommonInput;
import org.cryptimeleon.math.serialization.ObjectRepresentation;
import org.cryptimeleon.math.serialization.Representable;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.rings.zn.Zp;

public class CPY06XiGenerationResult implements Representable {

    private GroupElement Pi;

    private FiatShamirProof proof;

    public CPY06XiGenerationResult(GroupElement Pi, FiatShamirProof proof) {
        this.Pi = Pi;
        this.proof = proof;
    }

    public CPY06XiGenerationResult(Representation repr, CPY06PublicParameters pp, GroupElement I, Zp.ZpElement u,
                                   Zp.ZpElement v) {
        ObjectRepresentation representation = (ObjectRepresentation) repr;

        this.Pi = pp.getBilGroup().getG1().restoreElement(representation.get("Pi"));

        CPY06XiProofCommonInput xiProofCommonInput = new CPY06XiProofCommonInput(this.Pi, I, u, v);

        FiatShamirProofSystem proofSystem = new FiatShamirProofSystem(new CPY06XiProof(pp));
        this.proof = proofSystem.restoreProof(xiProofCommonInput, representation.get("proof"));
    }

    public GroupElement getPi() {
        return Pi;
    }

    public FiatShamirProof getProof() {
        return proof;
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation repr = new ObjectRepresentation();
        repr.put("Pi", Pi.getRepresentation());
        repr.put("proof", proof.getRepresentation());
        return repr;
    }
}
