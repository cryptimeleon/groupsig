package org.cryptimeleon.groupsig.CPY06.issuing_protocol;

import org.cryptimeleon.craco.protocols.arguments.fiatshamir.FiatShamirProof;
import org.cryptimeleon.craco.protocols.arguments.fiatshamir.FiatShamirProofSystem;
import org.cryptimeleon.groupsig.CPY06.CPY06PublicParameters;
import org.cryptimeleon.groupsig.CPY06.issuing_protocol.pok.CPY06XiProof;
import org.cryptimeleon.groupsig.CPY06.issuing_protocol.pok.CPY06XiProofCommonInput;
import org.cryptimeleon.math.serialization.ObjectRepresentation;
import org.cryptimeleon.math.serialization.Representable;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
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

        CPY06XiProofCommonInput xiProofCommonInput = new CPY06XiProofCommonInput(pp, this.Pi, I, u, v);

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
