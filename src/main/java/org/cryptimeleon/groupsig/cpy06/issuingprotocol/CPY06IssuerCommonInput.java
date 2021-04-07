package org.cryptimeleon.groupsig.cpy06.issuingprotocol;

import org.cryptimeleon.craco.protocols.CommonInput;
import org.cryptimeleon.groupsig.cpy06.CPY06PublicParameters;

public class CPY06IssuerCommonInput implements CommonInput {

    private final CPY06PublicParameters pp;
    private final Integer newMemberIdentity;

    public CPY06IssuerCommonInput(CPY06PublicParameters pp, Integer newMemberIdentity) {
        this.pp = pp;
        this.newMemberIdentity = newMemberIdentity;
    }

    public CPY06PublicParameters getPp() {
        return pp;
    }

    public Integer getNewMemberIdentity() {
        return newMemberIdentity;
    }
}
