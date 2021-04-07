package org.cryptimeleon.groupsig.cpy06.issuingprotocol.joinpok;

import org.cryptimeleon.craco.protocols.CommonInput;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.rings.zn.Zn;

public class CPY06XiProofCommonInput implements CommonInput {

    private final GroupElement Pi;
    private final GroupElement I;
    private final Zn.ZnElement u;
    private final Zn.ZnElement v;

    public CPY06XiProofCommonInput(GroupElement Pi, GroupElement i, Zn.ZnElement u, Zn.ZnElement v) {
        this.Pi = Pi;
        I = i;
        this.u = u;
        this.v = v;
    }

    public GroupElement getPi() {
        return Pi;
    }

    public GroupElement getI() {
        return I;
    }

    public Zn.ZnElement getU() {
        return u;
    }

    public Zn.ZnElement getV() {
        return v;
    }
}
