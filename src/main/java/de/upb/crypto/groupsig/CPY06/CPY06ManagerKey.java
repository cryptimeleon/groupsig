package de.upb.crypto.groupsig.CPY06;

import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.ReprUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.rings.zn.Zp;

import java.util.Objects;

/**
 * Opener and Issuer keys are the same for this construction so we use the manager key to implement them both at once.
 */
public abstract class CPY06ManagerKey {

    @Represented(restorer = "Zp")
    private Zp.ZpElement gamma, zeta1, zeta2;

    public CPY06ManagerKey(Zp.ZpElement gamma, Zp.ZpElement zeta1, Zp.ZpElement zeta2) {
        this.gamma = gamma;
        this.zeta1 = zeta1;
        this.zeta2 = zeta2;
    }

    public CPY06ManagerKey(Representation repr, Zp zp) {
        new ReprUtil(this).register(zp, "Zp").deserialize(repr);
    }

    public Zp.ZpElement getGamma() {
        return gamma;
    }

    public Zp.ZpElement getZeta1() {
        return zeta1;
    }

    public Zp.ZpElement getZeta2() {
        return zeta2;
    }

    @Override
    public int hashCode() {
        return Objects.hash(gamma, zeta1, zeta2);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        CPY06ManagerKey other = (CPY06ManagerKey) obj;
        return Objects.equals(gamma, other.gamma)
                && Objects.equals(zeta1, other.zeta1)
                && Objects.equals(zeta1, other.zeta2);
    }
}
