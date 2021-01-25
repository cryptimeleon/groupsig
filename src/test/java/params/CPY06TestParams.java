package de.upb.crypto.craco.groupsig.params;

import de.upb.crypto.craco.common.interfaces.PlainText;
import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import de.upb.crypto.craco.groupsig.CPY06.CPY06GroupMembershipList;
import de.upb.crypto.craco.groupsig.CPY06.CPY06RevocationList;
import de.upb.crypto.craco.groupsig.CPY06.CPY06Setup;
import de.upb.crypto.craco.groupsig.CPY06.CPY06SignatureScheme;
import de.upb.crypto.craco.groupsig.GroupSignatureTestParam;
import de.upb.crypto.craco.common.TestParameterProvider;
import de.upb.crypto.craco.groupsig.interfaces.GroupSignatureScheme;
import de.upb.crypto.math.pairings.counting.CountingBilinearGroup;
import de.upb.crypto.math.pairings.generic.BilinearGroup;

public class CPY06TestParams implements TestParameterProvider {
    public GroupSignatureTestParam get() {
        BilinearGroup bilGroup = new CountingBilinearGroup(80, BilinearGroup.Type.TYPE_1);

        CPY06Setup setup = new CPY06Setup();
        setup.setup(bilGroup);
        GroupSignatureScheme scheme = new CPY06SignatureScheme(setup.getPublicParameters());

        PlainText plainText1 = new ByteArrayImplementation("Hello, PlainText1".getBytes());
        PlainText plainText2 = new ByteArrayImplementation("Goodbye, PlainText2".getBytes());

        return new GroupSignatureTestParam(
                scheme, setup.getOpenerKey(), setup.getIssuerKey(), new CPY06GroupMembershipList(),
                new CPY06RevocationList(), plainText1, plainText2
        );
    }
}
