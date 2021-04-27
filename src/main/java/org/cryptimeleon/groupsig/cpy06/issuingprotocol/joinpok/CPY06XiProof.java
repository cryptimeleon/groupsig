package org.cryptimeleon.groupsig.cpy06.issuingprotocol.joinpok;

import org.cryptimeleon.craco.protocols.CommonInput;
import org.cryptimeleon.craco.protocols.SecretInput;
import org.cryptimeleon.craco.protocols.arguments.sigma.ZnChallengeSpace;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.DelegateProtocol;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.LinearStatementFragment;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.SendThenDelegateFragment.ProverSpec;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.SendThenDelegateFragment.ProverSpecBuilder;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.SendThenDelegateFragment.SubprotocolSpec;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.SendThenDelegateFragment.SubprotocolSpecBuilder;
import org.cryptimeleon.craco.protocols.arguments.sigma.schnorr.variables.SchnorrZnVariable;
import org.cryptimeleon.groupsig.cpy06.CPY06PublicParameters;
import org.cryptimeleon.math.expressions.bool.GroupEqualityExpr;

/**
 * Implements PoK from the Join protocol from [NguSaf04], Section 4.2.
 *
 * Is a proof of knowledge of \((x_i, r')\) such that \(P_i = x_i P and v P + u I - P_i = r' H\).
 */
public class CPY06XiProof extends DelegateProtocol {

    private final CPY06PublicParameters pp;

    public CPY06XiProof(CPY06PublicParameters pp) {
        this.pp = pp;
    }

    @Override
    protected ProverSpec provideProverSpecWithNoSendFirst(CommonInput commonInput, SecretInput secretInput,
                                                          ProverSpecBuilder builder) {
        if (!(secretInput instanceof CPY06XiProofSecretInput)) {
            throw new IllegalArgumentException("SecretInput " + secretInput + " is not a CPY06XiProofSecretInput");
        }
        CPY06XiProofSecretInput xiProofSecretInput = (CPY06XiProofSecretInput) secretInput;

        builder.putWitnessValue("x", xiProofSecretInput.getX());
        builder.putWitnessValue("rPrime", xiProofSecretInput.getrPrime());

        return builder.build();
    }

    @Override
    protected SubprotocolSpec provideSubprotocolSpec(CommonInput commonInput, SubprotocolSpecBuilder builder) {
        if (!(commonInput instanceof CPY06XiProofCommonInput)) {
            throw new IllegalArgumentException("CommonInput " + commonInput + " is not a CPY06XiProofCommonInput");
        }
        CPY06XiProofCommonInput xiProofCommonInput = (CPY06XiProofCommonInput) commonInput;
        SchnorrZnVariable xVar = builder.addZnVariable(
                "x",
                pp.getBilGroup().getG1().getZn()
        );
        SchnorrZnVariable rPrimeVar = builder.addZnVariable(
                "rPrime",
                pp.getBilGroup().getG1().getZn()
        );

        // P_i = x_i P
        GroupEqualityExpr xStatement = xiProofCommonInput.getPi().expr()
                .isEqualTo(pp.getP1().pow(xVar));

        // v P + u I - P_i = r' H
        GroupEqualityExpr rPrimeStatement = pp.getP1().pow(xiProofCommonInput.getV())
                .op(xiProofCommonInput.getI().pow(xiProofCommonInput.getU()))
                .op(xiProofCommonInput.getPi().inv())
                .expr().isEqualTo(pp.getZ().pow(rPrimeVar));

        builder.addSubprotocol("PiCorrect", new LinearStatementFragment(xStatement));
        builder.addSubprotocol("xiComputedCorrectly", new LinearStatementFragment(rPrimeStatement));

        return builder.build();
    }

    @Override
    public ZnChallengeSpace getChallengeSpace(CommonInput commonInput) {
        return new ZnChallengeSpace(pp.getBilGroup().getG1().getZn());
    }
}
