package org.cryptimeleon.groupsig.cpy06.claimpok;

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
import org.cryptimeleon.groupsig.cpy06.CPY06Signature;
import org.cryptimeleon.math.expressions.bool.GroupEqualityExpr;
import org.cryptimeleon.math.structures.rings.zn.Zp;

public class CPY06ClaimFSProof extends DelegateProtocol {

    CPY06PublicParameters pp;

    public CPY06ClaimFSProof(CPY06PublicParameters pp) {
        this.pp = pp;
    }

    @Override
    protected ProverSpec provideProverSpecWithNoSendFirst(CommonInput commonInput, SecretInput secretInput,
                                                          ProverSpecBuilder builder) {
        if (!(secretInput instanceof CPY06ClaimFSProofSecretInput)) {
            throw new IllegalArgumentException("SecretInput " + secretInput + " is not a CPY06XiProofSecretInput");
        }
        Zp.ZpElement x = ((CPY06ClaimFSProofSecretInput) secretInput).getX();

        builder.putWitnessValue("x", x);

        return builder.build();
    }

    @Override
    protected SubprotocolSpec provideSubprotocolSpec(CommonInput commonInput, SubprotocolSpecBuilder builder) {
        if (!(commonInput instanceof CPY06Signature)) {
            throw new IllegalArgumentException("CommonInput " + commonInput + " is not a CPY06Signature");
        }
        CPY06Signature signature = (CPY06Signature) commonInput;
        SchnorrZnVariable xVar = builder.addZnVariable(
                "x",
                pp.getBilGroup().getG1().getZn()
        );

        // e(P_1, T_4)^x = T_5
        GroupEqualityExpr xStatement = pp.getBilGroup().getBilinearMap().applyExpr(pp.getP1(), signature.getT4())
                .pow(xVar)
                .isEqualTo(signature.getT5());

        builder.addSubprotocol("xCorrect", new LinearStatementFragment(xStatement));

        return builder.build();
    }

    @Override
    public ZnChallengeSpace getChallengeSpace(CommonInput commonInput) {
        return new ZnChallengeSpace(pp.getBilGroup().getZn());
    }
}
