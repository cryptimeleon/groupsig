package org.cryptimeleon.groupsig.CPY06.issuing_protocol;

import org.cryptimeleon.math.serialization.Representable;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.structures.groups.GroupElement;

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
