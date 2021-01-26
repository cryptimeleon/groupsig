package de.upb.crypto.groupsig.CPY06.issuing_protocol;

import de.upb.crypto.groupsig.CPY06.CPY06GMLEntry;
import de.upb.crypto.groupsig.CPY06.CPY06IssuerKey;
import de.upb.crypto.groupsig.CPY06.CPY06ManagerKey;
import de.upb.crypto.groupsig.CPY06.CPY06PublicParameters;
import de.upb.crypto.groupsig.interfaces.protocol.IssuingProtocol;
import de.upb.crypto.groupsig.interfaces.protocol.IssuingProtocolInstance;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.zn.Zp;

public class CPY06IssuingProtocolIssuerInstance implements IssuingProtocolInstance {

    private CPY06IssuingProtocol protocol;
    private CPY06PublicParameters pp;
    private CPY06ManagerKey issuerKey;

    private State state;

    private Zp.ZpElement u, v, t;

    private GroupElement C, A;

    private Integer memberIdentity;

    public enum State {
        SENDING_XI_GENERATION_CHALLENGE,
        GENERATING_MEMBER_KEY,
        DONE
    }

    public CPY06IssuingProtocolIssuerInstance(CPY06IssuingProtocol protocol, CPY06PublicParameters pp,
                                              CPY06IssuerKey issuerKey) {
        this.protocol = protocol;
        this.pp = pp;
        this.issuerKey = issuerKey;
        this.state = State.SENDING_XI_GENERATION_CHALLENGE;
    }

    @Override
    public IssuingProtocol getProtocol() {
        return protocol;
    }

    @Override
    public String getRoleName() {
        return IssuingProtocol.ISSUER_ROLE;
    }

    public CPY06XiGenerationChallenge createXiGenerationChallenge() {
        // Second step from protocol in [NguSaf04]
        Zp zp = (Zp) pp.getBilGroup().getZn();
        u = zp.getUniformlyRandomUnit();
        v = zp.getUniformlyRandomUnit();
        return new CPY06XiGenerationChallenge(u, v);
    }

    @Override
    public Representation nextMessage(Representation received) {
        switch (state) {
            case SENDING_XI_GENERATION_CHALLENGE:
                return createXiGenerationChallenge().getRepresentation();
            case GENERATING_MEMBER_KEY:
                // Chose t_i <-R Z_p^*, compute A_i = 1/(t_i + gamma)(x_i * P_1 + Q)
                //  and send (i, A_i, t_i) to user.
                break;
            case DONE: // we are done already and should not reach this
                return null;
            default:
                throw new IllegalStateException("Unsupported state " + state);
        }
        return null;
    }

    @Override
    public boolean hasTerminated() {
        return state == State.DONE;
    }

    /**
     * Once the protocol is finished this can be used to obtain the GML Entry for the new group member.
     */
    public CPY06GMLEntry getGroupMembershipListEntry() {
        if (hasTerminated()) {
            return new CPY06GMLEntry(memberIdentity, C, A, t);
        } else {
            throw new IllegalStateException("Protocol is not done yet. Cannot generate GML entry");
        }
    }
}
