package de.upb.crypto.groupsig.CPY06;

import de.upb.crypto.groupsig.common.GroupSignature;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.ReprUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.groups.GroupElement;
import de.upb.crypto.math.structures.groups.elliptic.BilinearGroup;
import de.upb.crypto.math.structures.rings.zn.Zp;

import java.util.Objects;

public class CPY06Signature implements GroupSignature {

    @Represented(restorer = "G1")
    private GroupElement T1, T2, T3;
    @Represented(restorer = "G2")
    private GroupElement T4;
    @Represented(restorer = "GT")
    private GroupElement T5;

    @Represented(restorer = "Zp")
    private Zp.ZpElement c;
    @Represented(restorer = "Zp")
    private Zp.ZpElement sr1, sr2, sd1, sd2, sx, st;

    public CPY06Signature(GroupElement t1, GroupElement t2, GroupElement t3, GroupElement t4, GroupElement t5,
                          Zp.ZpElement c, Zp.ZpElement sr1, Zp.ZpElement sr2, Zp.ZpElement sd1, Zp.ZpElement sd2,
                          Zp.ZpElement sx, Zp.ZpElement st) {
        T1 = t1;
        T2 = t2;
        T3 = t3;
        T4 = t4;
        T5 = t5;
        this.c = c;
        this.sr1 = sr1;
        this.sr2 = sr2;
        this.sd1 = sd1;
        this.sd2 = sd2;
        this.sx = sx;
        this.st = st;
    }

    public CPY06Signature(Representation repr, BilinearGroup bilGroup) {
        new ReprUtil(this).register(bilGroup.getBilinearMap()).register((Zp) bilGroup.getZn(), "Zp")
                .deserialize(repr);
    }

    public GroupElement getT1() {
        return T1;
    }

    public GroupElement getT2() {
        return T2;
    }

    public GroupElement getT3() {
        return T3;
    }

    public GroupElement getT4() {
        return T4;
    }

    public GroupElement getT5() {
        return T5;
    }

    public Zp.ZpElement getC() {
        return c;
    }

    public Zp.ZpElement getSr1() {
        return sr1;
    }

    public Zp.ZpElement getSr2() {
        return sr2;
    }

    public Zp.ZpElement getSd1() {
        return sd1;
    }

    public Zp.ZpElement getSd2() {
        return sd2;
    }

    public Zp.ZpElement getSx() {
        return sx;
    }

    public Zp.ZpElement getSt() {
        return st;
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public int hashCode() {
        return Objects.hash(T1, T2, T3, T4, T5, c, sr1, sr2, sd1, sd2, sx, st);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        CPY06Signature other = (CPY06Signature) obj;
        return Objects.equals(T1, other.T1)
                && Objects.equals(T2, other.T2)
                && Objects.equals(T3, other.T3)
                && Objects.equals(T4, other.T4)
                && Objects.equals(T5, other.T5)
                && Objects.equals(c, other.c)
                && Objects.equals(sr1, other.sr1)
                && Objects.equals(sr2, other.sr2)
                && Objects.equals(sd1, other.sd1)
                && Objects.equals(sd2, other.sd2)
                && Objects.equals(sx, other.sx)
                && Objects.equals(st, other.st);
    }
}
