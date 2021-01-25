package de.upb.crypto.craco.groupsig.interfaces.protocol;

public interface TwoPartyProtocol {
    TwoPartyProtocolInstance instantiateProtocol(String role, CommonInput commonInput, SecretInput secretInput);
    String[] getRoleNames();

    /**
     * Returns the role that sends the first message.
     */
    String getFirstMessageRole();
}
