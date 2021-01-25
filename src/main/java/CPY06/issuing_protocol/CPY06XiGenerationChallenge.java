package de.upb.crypto.craco.groupsig.CPY06.issuing_protocol;

import de.upb.crypto.math.serialization.Representable;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;
import de.upb.crypto.math.structures.zn.Zp;

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
