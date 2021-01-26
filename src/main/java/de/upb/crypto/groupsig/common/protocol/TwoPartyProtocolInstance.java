package de.upb.crypto.groupsig.interfaces.protocol;

import de.upb.crypto.math.serialization.Representation;

public interface TwoPartyProtocolInstance {
    de.upb.crypto.groupsig.interfaces.protocol.TwoPartyProtocol getProtocol();
    String getRoleName();

    /**
     * Returns true iff this role sends the first message of this protocol
     */
    default boolean sendsFirstMessage() {
        return getProtocol().getFirstMessageRole().equals(getRoleName());
    }

    /**
     * Outputs the next message this protocol instance demands to be sent to the other party.
     * @param received The message recently received from the other party
     *                 (or null if this is the first round and no messages have been sent yet)
     * @return The message m to be sent to the other party (who then calls nextMessage(m) on their end).
     *         If nextMessage() returns null, the protocol has terminated.
     */
    Representation nextMessage(Representation received);

    /**
     * Returns true if the protocol is done (i.e. no further calls to nextMessage() are necessary).
     */
    boolean hasTerminated();
}
