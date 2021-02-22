package org.cryptimeleon.groupsig.CPY06;

import org.cryptimeleon.groupsig.common.MemberKey;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.rings.zn.Zp;

import java.util.Objects;

public class CPY06MemberKey implements MemberKey {

    @Represented
    private Integer identity;

    @Represented(restorer = "G1")
    private GroupElement A;

    @Represented(restorer = "Zp")
    private Zp.ZpElement t, x;

    public CPY06MemberKey(Integer identity, GroupElement a, Zp.ZpElement t, Zp.ZpElement x) {
        this.identity = identity;
        A = a;
        this.t = t;
        this.x = x;
    }

    public CPY06MemberKey(Representation repr, Group g1, Zp zp) {
        new ReprUtil(this).register(g1, "G1").register(zp, "Zp").deserialize(repr);
    }

    @Override
    public Integer getIdentity() {
        return identity;
    }

    public GroupElement getA() {
        return A;
    }

    public Zp.ZpElement getT() {
        return t;
    }

    public Zp.ZpElement getX() {
        return x;
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public int hashCode() {
        return Objects.hash(identity, A, t, x);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        CPY06MemberKey other = (CPY06MemberKey) obj;
        return Objects.equals(identity, other.identity)
                && Objects.equals(A, other.A)
                && Objects.equals(t, other.t)
                && Objects.equals(x, other.x);
    }
}
