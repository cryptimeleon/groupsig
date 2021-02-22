package org.cryptimeleon.groupsig.common.protocol;

public interface IssuingProtocol extends TwoPartyProtocol {

    String USER_ROLE = "user";
    String ISSUER_ROLE = "issuer";

    @Override
    default String[] getRoleNames() {
        return new String[] {USER_ROLE, ISSUER_ROLE};
    }

    @Override
    IssuingProtocolInstance instantiateProtocol(String role, CommonInput commonInput, SecretInput secretInput);

    default IssuingProtocolInstance instantiateUser(CommonInput commonInput, SecretInput memberKey) {
        return instantiateProtocol(USER_ROLE, commonInput, memberKey);
    }

    default IssuingProtocolInstance instantiateIssuer(CommonInput commonInput, SecretInput issuerKey) {
        return instantiateProtocol(ISSUER_ROLE, commonInput, issuerKey);
    }
}
