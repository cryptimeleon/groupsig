package de.upb.crypto.groupsig.CPY06.issuing_protocol;

import de.upb.crypto.math.serialization.Representable;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.ReprUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.rings.zn.Zp;

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
