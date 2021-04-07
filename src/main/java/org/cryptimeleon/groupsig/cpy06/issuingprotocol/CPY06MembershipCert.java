package org.cryptimeleon.groupsig.cpy06.issuingprotocol;

import org.cryptimeleon.math.serialization.Representable;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.rings.zn.Zp;

public class CPY06MembershipCert implements Representable {

    @Represented
    private Integer identity;

    @Represented(restorer = "G1")
    private GroupElement A;

    @Represented(restorer = "Zp")
    private Zp.ZpElement t;

    public CPY06MembershipCert(Integer identity, GroupElement a, Zp.ZpElement t) {
        this.identity = identity;
        A = a;
        this.t = t;
    }

    public CPY06MembershipCert(Representation repr, Group g1, Zp zp) {
        new ReprUtil(this).register(g1, "G1").register(zp, "Zp").deserialize(repr);
    }

    public Integer getIdentity() {
        return identity;
    }

    public GroupElement getA() {
        return A;
    }

    public Zp.ZpElement getT() {
        return t;
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }
}
