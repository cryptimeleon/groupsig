package de.upb.crypto.craco.groupsig.CPY06;

import de.upb.crypto.craco.common.interfaces.PublicParameters;
import de.upb.crypto.craco.groupsig.interfaces.protocol.CommonInput;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.pairings.generic.BilinearGroup;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.serialization.annotations.v2.Represented;
import de.upb.crypto.math.structures.zn.HashIntoZp;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.Objects;

/**
 * The group public key for the scheme.
 */
public class CPY06PublicParameters implements PublicParameters, CommonInput {

    @Represented
    private BilinearGroup bilGroup;

    private final Zp zp;

    @Represented(restorer = "bilGroup::getG1")
    private GroupElement P1;
    @Represented(restorer = "bilGroup::getG2")
    private GroupElement P2;

    @Represented(restorer = "bilGroup::getG1")
    private GroupElement Q;
    @Represented(restorer = "bilGroup::getG2")
    private GroupElement R, W;
    @Represented(restorer = "bilGroup::getG1")
    private GroupElement X, Y, Z;

    private HashIntoZp hashFunction;

    public CPY06PublicParameters(BilinearGroup bilGroup, GroupElement p1, GroupElement p2, GroupElement q, GroupElement r,
                               GroupElement w, GroupElement x, GroupElement y, GroupElement z) {
        this.bilGroup = bilGroup;
        zp = new Zp(bilGroup.getZn().size());
        P1 = p1;
        P2 = p2;
        Q = q;
        R = r;
        W = w;
        X = x;
        Y = y;
        Z = z;
        hashFunction = new HashIntoZp(zp);
    }

    public CPY06PublicParameters(Representation repr) {
        new ReprUtil(this).deserialize(repr);
        zp = new Zp(bilGroup.getZn().size());
        hashFunction = new HashIntoZp(zp);
    }

    public BilinearGroup getBilGroup() {
        return bilGroup;
    }

    public Zp getZp() {
        return zp;
    }

    public GroupElement getP1() {
        return P1;
    }

    public GroupElement getP2() {
        return P2;
    }

    public GroupElement getQ() {
        return Q;
    }

    public GroupElement getR() {
        return R;
    }

    public GroupElement getW() {
        return W;
    }

    public GroupElement getX() {
        return X;
    }

    public GroupElement getY() {
        return Y;
    }

    public GroupElement getZ() {
        return Z;
    }

    public HashIntoZp getHashFunction() {
        return hashFunction;
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public int hashCode() {
        return Objects.hash(bilGroup, P1, P2, Q, R, W, X, Y, Z, hashFunction);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        CPY06PublicParameters other = (CPY06PublicParameters) obj;
        return Objects.equals(bilGroup, other.bilGroup)
                && Objects.equals(P1, other.P1)
                && Objects.equals(P2, other.P2)
                && Objects.equals(Q, other.Q)
                && Objects.equals(R, other.R)
                && Objects.equals(W, other.W)
                && Objects.equals(X, other.X)
                && Objects.equals(Y, other.Y)
                && Objects.equals(Z, other.Z)
                && Objects.equals(hashFunction, other.hashFunction);
    }
}
