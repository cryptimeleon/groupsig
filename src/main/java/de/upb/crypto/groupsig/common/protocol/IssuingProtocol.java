package de.upb.crypto.groupsig.interfaces.protocol;

public interface IssuingProtocol extends de.upb.crypto.groupsig.interfaces.protocol.TwoPartyProtocol {

    String USER_ROLE = "user";
    String ISSUER_ROLE = "issuer";

    @Override
    default String[] getRoleNames() {
        return new String[] {USER_ROLE, ISSUER_ROLE};
    }

    @Override
    de.upb.crypto.groupsig.interfaces.protocol.IssuingProtocolInstance instantiateProtocol(String role, de.upb.crypto.groupsig.interfaces.protocol.CommonInput commonInput, de.upb.crypto.groupsig.interfaces.protocol.SecretInput secretInput);

    default de.upb.crypto.groupsig.interfaces.protocol.IssuingProtocolInstance instantiateUser(de.upb.crypto.groupsig.interfaces.protocol.CommonInput commonInput, de.upb.crypto.groupsig.interfaces.protocol.SecretInput memberKey) {
        return instantiateProtocol(USER_ROLE, commonInput, memberKey);
    }

    default de.upb.crypto.groupsig.interfaces.protocol.IssuingProtocolInstance instantiateIssuer(de.upb.crypto.groupsig.interfaces.protocol.CommonInput commonInput, de.upb.crypto.groupsig.interfaces.protocol.SecretInput issuerKey) {
        return instantiateProtocol(ISSUER_ROLE, commonInput, issuerKey);
    }
}
