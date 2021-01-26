package de.upb.crypto.groupsig.CPY06.issuing_protocol;

import de.upb.crypto.groupsig.CPY06.CPY06IssuerKey;
import de.upb.crypto.groupsig.CPY06.CPY06PublicParameters;
import de.upb.crypto.groupsig.interfaces.protocol.CommonInput;
import de.upb.crypto.groupsig.interfaces.protocol.IssuingProtocol;
import de.upb.crypto.groupsig.interfaces.protocol.IssuingProtocolInstance;
import de.upb.crypto.groupsig.interfaces.protocol.SecretInput;

/**
 * The member key issuing protocol in [de.upb.crypto.groupsig.CPY06] is partially based on the join protocol from [NguSaf04], Section 4.2.
 * Their protocol is used to choose a random non-adaptive x_i.
 *
 * [NguSaf04] Nguyen, Lan and Safavi-Naini, Rei
 * Efficient and Provably Secure Trapdoor-free Group Signature Schemes from Bilinear Pairings
 */
public class CPY06IssuingProtocol implements IssuingProtocol {
    
    @Override
    public IssuingProtocolInstance instantiateProtocol(String role, CommonInput commonInput, SecretInput secretInput) {
        if (!(commonInput instanceof CPY06PublicParameters)) {
            throw new IllegalArgumentException("CommonInput " + commonInput + " is not a CPY06PublicParameters");
        }
        if (role.equals(IssuingProtocol.ISSUER_ROLE) && !(secretInput instanceof CPY06IssuerKey)) {
            throw new IllegalArgumentException("SecretInput " + secretInput
                    + " is not a CPY06IssuerKey as required for the issuer role");
        }
        CPY06PublicParameters pp = (CPY06PublicParameters) commonInput;

        if (role.equals(ISSUER_ROLE)) {
            CPY06IssuerKey issuerKey = (CPY06IssuerKey) secretInput;
            return new CPY06IssuingProtocolIssuerInstance(this, pp, issuerKey);
        } else if (role.equals(USER_ROLE)) {
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
