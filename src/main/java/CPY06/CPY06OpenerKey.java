package de.upb.crypto.craco.groupsig.CPY06;

import de.upb.crypto.craco.groupsig.interfaces.OpenerKey;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.v2.ReprUtil;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.Objects;

public class CPY06OpenerKey extends CPY06ManagerKey implements OpenerKey {
    public CPY06OpenerKey(Zp.ZpElement gamma, Zp.ZpElement zeta1, Zp.ZpElement zeta2) {
        super(gamma, zeta1, zeta2);
    }

    public CPY06OpenerKey(Representation repr, Zp zp) {
        super(repr, zp);
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        CPY06OpenerKey other = (CPY06OpenerKey) obj;
        return Objects.equals(super.getGamma(), other.getGamma())
                && Objects.equals(super.getZeta1(), other.getZeta1())
                && Objects.equals(super.getZeta2(), other.getZeta2());
    }
}
