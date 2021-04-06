package org.cryptimeleon.groupsig.cpy06.issuingprotocol.joinpok;

import org.cryptimeleon.craco.protocols.SecretInput;
import org.cryptimeleon.math.structures.rings.zn.Zn;

public class CPY06XiProofSecretInput implements SecretInput {

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
