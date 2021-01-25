package de.upb.crypto.craco.groupsig.CPY06.issuing_protocol;

import de.upb.crypto.craco.groupsig.CPY06.CPY06MemberKey;
import de.upb.crypto.craco.groupsig.CPY06.CPY06PublicParameters;
import de.upb.crypto.craco.groupsig.interfaces.protocol.IssuingProtocol;
import de.upb.crypto.craco.groupsig.interfaces.protocol.IssuingProtocolInstance;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.zn.Zp;

public class CPY06IssuingProtocolUserInstance implements IssuingProtocolInstance {

    private CPY06IssuingProtocol protocol;
    private CPY06PublicParameters pp;

    private State state;
    
    private Zp.ZpElement y, r, u, v, x, t;

    private GroupElement Pi, A;

    private Integer identity;

    public enum State {
        START,
        GENERATING_XI,
        VERIFYING_KEY,
        VERIFIED_KEY
    }

    public CPY06IssuingProtocolUserInstance(CPY06IssuingProtocol protocol, CPY06PublicParameters pp) {
        this.protocol = protocol;
        this.pp = pp;
        this.state = State.START;
    }

    @Override
    public IssuingProtocol getProtocol() {
        return protocol;
    }

    @Override
    public String getRoleName() {
        return IssuingProtocol.USER_ROLE;
    }

    public GroupElement createXiGenerationAnnouncement() {
        // First step from protocol in [NguSaf04]
        // TODO (rh): P and H from [NguSaf04] are P_1 and Z in [CPY06]?
        Zp zp = (Zp) pp.getBilGroup().getZn();
        y = zp.getUniformlyRandomUnit();
        r = zp.getUniformlyRandomUnit();

        return pp.getP1().pow(y).op(pp.getZ().pow(r)).compute();
    }

    public CPY06XiGenerationResult createXiGenerationResult() {
        x = u.mul(y).add(v);
        Pi = pp.getP1().pow(x);
        // TODO (rh): Generate PoK for x_i and ur
        //  Just a Schnorr for two values, see [CamMic98], Section 4.2
        return new CPY06XiGenerationResult(Pi, null);
    }

    public Boolean verifyMembershipCert(CPY06MembershipCert membershipCert) {
        // A_i
        GroupElement leftSideG1 = membershipCert.getA();
        // t_i * P_2 + R
        GroupElement leftSideG2 = pp.getP2().pow(membershipCert.getT()).op(pp.getR());
        GroupElement leftSide = pp.getBilGroup().getBilinearMap().apply(leftSideG1, leftSideG2);
        // x_i * P_1 + Q
        GroupElement rightSideG1 = pp.getP1().pow(x).op(pp.getQ());
        // P_2
        GroupElement rightSideG2 = pp.getP2();
        GroupElement rightSide = pp.getBilGroup().getBilinearMap().apply(rightSideG1, rightSideG2);
        return leftSide.op(rightSide.inv()).isNeutralElement();
    }

    @Override
    public Representation nextMessage(Representation received) {
        switch (state) {
            case START:
                // Send I = yP + rH as in [NguSaf04]
                return createXiGenerationAnnouncement().getRepresentation();
            case GENERATING_XI:
                // Receive u, v from Issuer
                CPY06XiGenerationChallenge xiGenerationChallenge =
                        new CPY06XiGenerationChallenge(received, (Zp) pp.getBilGroup().getZn());
                u = xiGenerationChallenge.getU();
                v = xiGenerationChallenge.getV();
                // Generate x_i and send x_i * P_1 as well as PoK
                return createXiGenerationResult().getRepresentation();
            case VERIFYING_KEY:
                CPY06MembershipCert membershipCert = 
                        new CPY06MembershipCert(received, pp.getBilGroup().getG1(), (Zp) pp.getBilGroup().getZn());
                if (verifyMembershipCert(membershipCert)) {
                    identity = membershipCert.getIdentity();
                    A = membershipCert.getA();
                    t = membershipCert.getT();
                } else {
                    throw new IllegalArgumentException("Given CPY06MembershipCert does not verify successfully");
                }
                return null;
            case VERIFIED_KEY: // we are done already and should not reach this
                return null;
            default:
                throw new IllegalStateException("Unsupported state " + state);
        }
    }

    @Override
    public boolean hasTerminated() {
        return state == State.VERIFIED_KEY;
    }
    
    public CPY06MemberKey getResultingMemberKey() {
        if (hasTerminated()) {
            return new CPY06MemberKey(identity, A, t, x);
        } else {
            throw new IllegalStateException("Protocol is not done yet. Cannot generate member key");
        }
    }
}
