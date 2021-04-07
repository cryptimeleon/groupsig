package org.cryptimeleon.groupsig.cpy06;

import org.cryptimeleon.craco.protocols.SecretInput;
import org.cryptimeleon.groupsig.common.IssuerKey;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.structures.rings.zn.Zp;

import java.util.Objects;

public class CPY06IssuerKey extends CPY06ManagerKey implements IssuerKey, SecretInput {
    public CPY06IssuerKey(Zp.ZpElement gamma, Zp.ZpElement zeta1, Zp.ZpElement zeta2) {
        super(gamma, zeta1, zeta2);
    }

    public CPY06IssuerKey(Representation repr, Zp zp) {
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
        CPY06IssuerKey other = (CPY06IssuerKey) obj;
        return Objects.equals(super.getGamma(), other.getGamma())
                && Objects.equals(super.getZeta1(), other.getZeta1())
                && Objects.equals(super.getZeta2(), other.getZeta2());
    }
}
