package org.cryptimeleon.groupsig.CPY06.issuing_protocol.pok;

import org.cryptimeleon.craco.protocols.CommonInput;
import org.cryptimeleon.groupsig.CPY06.CPY06PublicParameters;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.rings.zn.Zn;

public class CPY06XiProofCommonInput implements CommonInput {

    private final CPY06PublicParameters pp;
    private final GroupElement Pi;
    private final GroupElement I;
    private final Zn.ZnElement u;
    private final Zn.ZnElement v;

    public CPY06XiProofCommonInput(CPY06PublicParameters publicParameters, GroupElement Pi, GroupElement i, Zn.ZnElement u, Zn.ZnElement v) {
        this.pp = publicParameters;
        this.Pi = Pi;
        I = i;
        this.u = u;
        this.v = v;
    }

    public CPY06PublicParameters getPp() {
        return pp;
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
