package de.upb.crypto.groupsig.CPY06.issuing_protocol;

import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representable;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;

public class CPY06XiGenerationResult implements Representable {

    private GroupElement Pi;
    private Object proof;

    public CPY06XiGenerationResult(GroupElement Pi, Object proof) {
        this.Pi = Pi;
        this.proof = proof;
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }
}
