package org.cryptimeleon.groupsig.CPY06.issuing_protocol;

import org.cryptimeleon.math.serialization.Representable;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.rings.zn.Zn;
import org.cryptimeleon.math.structures.rings.zn.Zp;

public class CPY06XiGenerationChallenge implements Representable {

    @Represented(restorer = "Zp")
    private Zp.ZpElement u, v;

    public CPY06XiGenerationChallenge(Zp.ZpElement u, Zp.ZpElement v) {
        this.u = u;
        this.v = v;
    }

    public CPY06XiGenerationChallenge(Representation repr, Zp zp) {
        new ReprUtil(this).register(zp, "Zp").deserialize(repr);
    }

    public Zp.ZpElement getU() {
        return u;
    }

    public Zp.ZpElement getV() {
        return v;
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }
}
