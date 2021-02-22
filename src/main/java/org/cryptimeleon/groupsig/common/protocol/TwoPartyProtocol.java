package org.cryptimeleon.groupsig.common.protocol;

public interface TwoPartyProtocol {
    TwoPartyProtocolInstance instantiateProtocol(String role, CommonInput commonInput, SecretInput secretInput);
    String[] getRoleNames();

    /**
     * Returns the role that sends the first message.
     */
    String getFirstMessageRole();
}
