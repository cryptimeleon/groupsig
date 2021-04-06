package org.cryptimeleon.groupsig.CPY06.issuing_protocol;

import org.cryptimeleon.craco.protocols.CommonInput;
import org.cryptimeleon.craco.protocols.SecretInput;
import org.cryptimeleon.craco.protocols.arguments.fiatshamir.FiatShamirProof;
import org.cryptimeleon.craco.protocols.arguments.fiatshamir.FiatShamirProofSystem;
import org.cryptimeleon.groupsig.CPY06.CPY06MemberKey;
import org.cryptimeleon.groupsig.CPY06.CPY06PublicParameters;
import org.cryptimeleon.groupsig.CPY06.issuing_protocol.pok.CPY06XiProof;
import org.cryptimeleon.groupsig.CPY06.issuing_protocol.pok.CPY06XiProofCommonInput;
import org.cryptimeleon.groupsig.CPY06.issuing_protocol.pok.CPY06XiProofSecretInput;
import org.cryptimeleon.groupsig.common.protocol.IssuingProtocol;
import org.cryptimeleon.groupsig.common.protocol.IssuingProtocolInstance;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.rings.zn.Zn;
import org.cryptimeleon.math.structures.rings.zn.Zp;

public class CPY06IssuingProtocolUserInstance implements IssuingProtocolInstance {

    private final CPY06IssuingProtocol protocol;
    private final CPY06PublicParameters pp;

    private State state;
    
    private Zp.ZpElement y, r, u, v, x, t;

    private GroupElement A;
    private GroupElement I;

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

    @Override
    public Representation nextMessage(Representation received) {
        switch (state) {
            case START:
                // First step from protocol in [NguSaf04]
                // Send I = yP + rH as in [NguSaf04]
                state = State.GENERATING_XI;
                return createXiGenerationAnnouncement().getRepresentation();
            case GENERATING_XI:
                // Third and fourth steps from protocol in [NguSaf04]
                // Receive u, v from Issuer
                CPY06XiGenerationChallenge xiGenerationChallenge =
                        new CPY06XiGenerationChallenge(received, pp.getZp());
                u = xiGenerationChallenge.getU();
                v = xiGenerationChallenge.getV();
                // Generate x_i and send x_i * P_1 as well as PoK
                state = State.VERIFYING_KEY;
                return createXiGenerationResult().getRepresentation();
            case VERIFYING_KEY:
                // Third step from protocol in [CPY06]
                CPY06MembershipCert membershipCert = 
                        new CPY06MembershipCert(received, pp.getBilGroup().getG1(), pp.getZp());
                if (verifyMembershipCert(membershipCert)) {
                    identity = membershipCert.getIdentity();
                    A = membershipCert.getA();
                    t = membershipCert.getT();
                    state = State.VERIFIED_KEY;
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

    private GroupElement createXiGenerationAnnouncement() {
        Zp zp = pp.getZp();
        y = zp.getUniformlyRandomUnit();
        r = zp.getUniformlyRandomUnit();
        I = pp.getP1().pow(y).op(pp.getZ().pow(r)).compute();

        return I;
    }

    private CPY06XiGenerationResult createXiGenerationResult() {
        x = u.mul(y).add(v);
        GroupElement pi = pp.getP1().pow(x);

        FiatShamirProofSystem proofSystem = new FiatShamirProofSystem(new CPY06XiProof(pp));

        CommonInput commonInput = new CPY06XiProofCommonInput(pp, pi, I, u, v);
        // Calculation reveals rPrime = ur
        SecretInput secretInput = new CPY06XiProofSecretInput(x, u.mul(r));
        FiatShamirProof proof = proofSystem.createProof(commonInput, secretInput);
        return new CPY06XiGenerationResult(pi, proof);
    }

    private Boolean verifyMembershipCert(CPY06MembershipCert membershipCert) {
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
        return leftSide.equals(rightSide);
    }
}
