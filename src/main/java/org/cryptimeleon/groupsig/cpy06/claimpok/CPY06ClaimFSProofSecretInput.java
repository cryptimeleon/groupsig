package org.cryptimeleon.groupsig.cpy06.claimpok;

import org.cryptimeleon.craco.protocols.SecretInput;
import org.cryptimeleon.math.structures.rings.zn.Zp;

public class CPY06ClaimFSProofSecretInput implements SecretInput {
    Zp.ZpElement x;

    public CPY06ClaimFSProofSecretInput(Zp.ZpElement x) {
        this.x = x;
    }

    public Zp.ZpElement getX() {
        return x;
    }
}
