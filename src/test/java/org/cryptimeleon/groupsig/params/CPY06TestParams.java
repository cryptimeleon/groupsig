package org.cryptimeleon.groupsig.params;

import org.cryptimeleon.craco.common.ByteArrayImplementation;
import org.cryptimeleon.craco.common.TestParameterProvider;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.groupsig.cpy06.CPY06GroupMembershipList;
import org.cryptimeleon.groupsig.cpy06.CPY06RevocationList;
import org.cryptimeleon.groupsig.cpy06.CPY06Setup;
import org.cryptimeleon.groupsig.cpy06.CPY06SignatureScheme;
import org.cryptimeleon.groupsig.GroupSignatureTestParam;
import org.cryptimeleon.groupsig.common.GroupSignatureScheme;
import org.cryptimeleon.math.structures.groups.counting.CountingBilinearGroup;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearGroup;

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
