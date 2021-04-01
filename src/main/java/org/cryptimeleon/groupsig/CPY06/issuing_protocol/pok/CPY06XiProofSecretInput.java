package org.cryptimeleon.groupsig.CPY06.issuing_protocol.pok;

import org.cryptimeleon.math.structures.rings.zn.Zn;
import org.cryptimeleon.math.structures.rings.zn.Zp;

public class CPY06XiProofSecretInput {

    private final Zn.ZnElement x;
    private final Zn.ZnElement rPrime;

    public CPY06XiProofSecretInput(Zn.ZnElement x, Zn.ZnElement rPrime) {
        this.x = x;
        this.rPrime = rPrime;
    }

    public Zn.ZnElement getX() {
        return x;
    }

    public Zn.ZnElement getrPrime() {
        return rPrime;
    }
}
