package org.cryptimeleon.groupsig.cpy06.issuingprotocol;

import org.cryptimeleon.craco.protocols.arguments.fiatshamir.FiatShamirProofSystem;
import org.cryptimeleon.groupsig.common.protocol.IssuingProtocol;
import org.cryptimeleon.groupsig.common.protocol.IssuingProtocolInstance;
import org.cryptimeleon.groupsig.cpy06.CPY06GMLEntry;
import org.cryptimeleon.groupsig.cpy06.CPY06IssuerKey;
import org.cryptimeleon.groupsig.cpy06.CPY06ManagerKey;
import org.cryptimeleon.groupsig.cpy06.CPY06PublicParameters;
import org.cryptimeleon.groupsig.cpy06.issuingprotocol.joinpok.CPY06XiProof;
import org.cryptimeleon.groupsig.cpy06.issuingprotocol.joinpok.CPY06XiProofCommonInput;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.rings.zn.Zp;

public class CPY06IssuingProtocolIssuerInstance implements IssuingProtocolInstance {

    private final CPY06IssuingProtocol protocol;
    private final CPY06PublicParameters pp;
    private final CPY06ManagerKey issuerKey;

    private State state;

    private Zp.ZpElement u, v, t;

    // Pi corresponds to Ci from [CPY06]
    private GroupElement Pi, A, I;

    private final Integer memberIdentity;

    public enum State {
        SENDING_XI_GENERATION_CHALLENGE,
        GENERATING_MEMBER_KEY,
        SENT_KEY
    }

    public CPY06IssuingProtocolIssuerInstance(CPY06IssuingProtocol protocol, CPY06PublicParameters pp,
                                              CPY06IssuerKey issuerKey, Integer memberIdentity) {
        this.protocol = protocol;
        this.pp = pp;
        this.issuerKey = issuerKey;
        this.memberIdentity = memberIdentity;
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

    @Override
    public Representation nextMessage(Representation received) {
        switch (state) {
            case SENDING_XI_GENERATION_CHALLENGE:
                // Second step from protocol in [NguSaf04]
                I = pp.getBilGroup().getG1().restoreElement(received);
                state = State.GENERATING_MEMBER_KEY;
                return createXiGenerationChallenge().getRepresentation();
            case GENERATING_MEMBER_KEY:
                // Second step from protocol in [CPY06]
                CPY06XiGenerationResult xiGenerationResult = new CPY06XiGenerationResult(received, pp, I, u, v);
                Pi = xiGenerationResult.getPi();
                // Verify proof for generation of x_i
                CPY06XiProofCommonInput xiProofCommonInput = new CPY06XiProofCommonInput(Pi, I, u, v);
                FiatShamirProofSystem proofSystem = new FiatShamirProofSystem(new CPY06XiProof(pp));
                if (!proofSystem.checkProof(xiProofCommonInput, xiGenerationResult.getProof())) {
                    throw new IllegalArgumentException("Proof verification failed");
                }
                state = State.SENT_KEY;
                return createMembershipCert().getRepresentation();
            case SENT_KEY: // we are done already and should not reach this
                return null;
            default:
                throw new IllegalStateException("Unsupported state " + state);
        }
    }

    @Override
    public boolean hasTerminated() {
        return state == State.SENT_KEY;
    }

    /**
     * Once the protocol is finished this can be used to obtain the GML Entry for the new group member.
     */
    public CPY06GMLEntry getGroupMembershipListEntry() {
        if (hasTerminated()) {
            return new CPY06GMLEntry(memberIdentity, Pi, A, t);
        } else {
            throw new IllegalStateException("Protocol is not done yet. Cannot generate GML entry");
        }
    }

    private CPY06XiGenerationChallenge createXiGenerationChallenge() {
        Zp zp = pp.getZp();
        u = zp.getUniformlyRandomUnit();
        v = zp.getUniformlyRandomUnit();
        return new CPY06XiGenerationChallenge(u, v);
    }

    private CPY06MembershipCert createMembershipCert() {
        // Chose t_i <-R Z_p^*, compute A_i = 1/(t_i + gamma)(x_i * P_1 + Q)
        //  and send (i, A_i, t_i) to user
        Zp zp = pp.getZp();
        t = zp.getUniformlyRandomUnit();
        A = Pi.op(pp.getQ()).pow(t.add(issuerKey.getGamma()).inv());
        return new CPY06MembershipCert(memberIdentity, A, t);
    }
}
