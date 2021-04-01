package org.cryptimeleon.groupsig.CPY06.issuing_protocol;

import org.cryptimeleon.craco.protocols.CommonInput;
import org.cryptimeleon.craco.protocols.SecretInput;
import org.cryptimeleon.groupsig.CPY06.CPY06IssuerKey;
import org.cryptimeleon.groupsig.CPY06.CPY06PublicParameters;
import org.cryptimeleon.groupsig.common.protocol.IssuingProtocol;
import org.cryptimeleon.groupsig.common.protocol.IssuingProtocolInstance;

/**
 * The member key issuing protocol in [CPY06] is partially based on the join protocol from [NguSaf04], Section 4.2.
 * Their protocol is used to choose a random non-adaptive x_i.
 *
 * [NguSaf04] Nguyen, Lan and Safavi-Naini, Rei
 * Efficient and Provably Secure Trapdoor-free Group Signature Schemes from Bilinear Pairings
 */
public class CPY06IssuingProtocol implements IssuingProtocol {
    
    @Override
    public IssuingProtocolInstance instantiateProtocol(String role, CommonInput commonInput, SecretInput secretInput) {
        if (role.equals(IssuingProtocol.ISSUER_ROLE) && !(commonInput instanceof CPY06IssuerCommonInput)) {
            throw new IllegalArgumentException("CommonInput " + commonInput + " is not a CPY06IssuerCommonInput"
                    +  " as required for the issuer role");
        } else if (role.equals(IssuingProtocol.USER_ROLE) && !(commonInput instanceof CPY06PublicParameters)) {
            throw new IllegalArgumentException("CommonInput " + commonInput + " is not a CPY06PublicParameters"
                    + " as required for the user role");
        }
        if (role.equals(IssuingProtocol.ISSUER_ROLE) && !(secretInput instanceof CPY06IssuerKey)) {
            throw new IllegalArgumentException("SecretInput " + secretInput
                    + " is not a CPY06IssuerKey as required for the issuer role");
        }

        if (role.equals(ISSUER_ROLE)) {
            CPY06IssuerCommonInput issuerCommonInput = (CPY06IssuerCommonInput) commonInput;
            CPY06IssuerKey issuerKey = (CPY06IssuerKey) secretInput;
            return new CPY06IssuingProtocolIssuerInstance(this, issuerCommonInput.getPp(), issuerKey,
                    issuerCommonInput.getNewMemberIdentity());
        } else if (role.equals(USER_ROLE)) {
            CPY06PublicParameters pp = (CPY06PublicParameters) commonInput;
            return new CPY06IssuingProtocolUserInstance(this, pp);
        } else {
            throw new IllegalArgumentException("Protocol role " + role + " is not supported here");
        }
    }

    @Override
    public String getFirstMessageRole() {
        return USER_ROLE;
    }
}
