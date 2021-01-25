package de.upb.crypto.craco.groupsig.CPY06;

import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.pairings.counting.CountingBilinearGroup;
import de.upb.crypto.math.pairings.generic.BilinearGroup;
import de.upb.crypto.math.pairings.type1.supersingular.SupersingularBilinearGroup;
import de.upb.crypto.math.structures.zn.Zp;

public class CPY06Setup {

    CPY06PublicParameters publicParameters;
    CPY06OpenerKey openerKey;
    CPY06IssuerKey issuerKey;

    public void setup(int securityParameter, boolean debugMode) {
        if (debugMode) {
            this.setup(new CountingBilinearGroup(securityParameter, BilinearGroup.Type.TYPE_1));
        } else {
            this.setup(new SupersingularBilinearGroup(securityParameter));
        }
    }

    public void setup(BilinearGroup bilinearGroup) {
        GroupElement p1 = bilinearGroup.getG1().getGenerator().compute();
        GroupElement p2 = bilinearGroup.getG2().getGenerator().compute();

        Zp zp = new Zp(bilinearGroup.getZn().size());
        Zp.ZpElement gamma = zp.getUniformlyRandomUnit();
        Zp.ZpElement zeta1 = zp.getUniformlyRandomUnit();
        Zp.ZpElement zeta2 = zp.getUniformlyRandomUnit();
        openerKey = new CPY06OpenerKey(gamma, zeta1, zeta2);
        issuerKey = new CPY06IssuerKey(gamma, zeta1, zeta2);

        GroupElement q = bilinearGroup.getG1().getUniformlyRandomElement().compute();
        GroupElement r = p2.pow(gamma).compute();
        GroupElement w = bilinearGroup.getG2().getUniformlyRandomNonNeutral().compute();
        GroupElement z = bilinearGroup.getG1().getUniformlyRandomNonNeutral().compute();
        GroupElement x = z.pow(zeta1.inv()).compute();
        GroupElement y = z.pow(zeta2.inv()).compute();
        publicParameters = new CPY06PublicParameters(bilinearGroup, p1, p2, q, r, w, x, y, z);
    }

    public CPY06PublicParameters getPublicParameters() {
        return publicParameters;
    }

    public CPY06OpenerKey getOpenerKey() {
        return openerKey;
    }

    public CPY06IssuerKey getIssuerKey() {
        return issuerKey;
    }
}
