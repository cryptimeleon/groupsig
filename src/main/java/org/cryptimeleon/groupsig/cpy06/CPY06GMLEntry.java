package org.cryptimeleon.groupsig.cpy06;

import org.cryptimeleon.groupsig.common.GMLEntry;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.Group;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.rings.zn.Zp;

import java.util.Objects;

public class CPY06GMLEntry implements GMLEntry {

    @Represented
    private Integer identity;

    @Represented(restorer = "G1")
    private GroupElement C, A;

    @Represented(restorer = "Zp")
    private Zp.ZpElement t;

    public CPY06GMLEntry(Integer identity, GroupElement c, GroupElement a, Zp.ZpElement t) {
        this.identity = identity;
        C = c;
        A = a;
        this.t = t;
    }

    public CPY06GMLEntry(Representation repr, Group g1, Zp zp) {
        new ReprUtil(this).register(g1, "G1").register(zp, "Zp").deserialize(repr);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    public Integer getIdentity() {
        return identity;
    }

    public GroupElement getC() {
        return C;
    }

    public GroupElement getA() {
        return A;
    }

    public Zp.ZpElement getT() {
        return t;
    }

    @Override
    public int hashCode() {
        return Objects.hash(identity, C, A , t);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        CPY06GMLEntry other = (CPY06GMLEntry) obj;
        return Objects.equals(identity, other.identity)
                && Objects.equals(C, other.C)
                && Objects.equals(A, other.A)
                && Objects.equals(t, other.t);
    }
}
