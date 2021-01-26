package de.upb.crypto.groupsig.interfaces.protocol;

public interface TwoPartyProtocol {
    de.upb.crypto.groupsig.interfaces.protocol.TwoPartyProtocolInstance instantiateProtocol(String role, de.upb.crypto.groupsig.interfaces.protocol.CommonInput commonInput, de.upb.crypto.groupsig.interfaces.protocol.SecretInput secretInput);
    String[] getRoleNames();

    /**
     * Returns the role that sends the first message.
     */
    String getFirstMessageRole();
}
