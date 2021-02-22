package org.cryptimeleon.groupsig;

import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.groupsig.common.*;
import org.cryptimeleon.groupsig.common.*;

/**
 * Class containing a set of parameters for testing a {@link GroupSignatureScheme}.
 *
 * <p>If your scheme does not support the {@link GroupSignatureScheme#reveal(GroupMembershipList, Integer, RevocationList)}
 * method, you may set {@code revocationList} to null.
 */
public class GroupSignatureTestParam {
    private Class<? extends GroupSignatureScheme> clazz;
    private GroupSignatureScheme scheme;
    private OpenerKey openerKey;
    private IssuerKey issuerKey;
    private GroupMembershipList groupMembershipList;
    private RevocationList revocationList;

    private PlainText plainText1;
    private PlainText plainText2;

    public GroupSignatureTestParam(GroupSignatureScheme scheme, OpenerKey openerKey, IssuerKey issuerKey,
                                   GroupMembershipList groupMembershipList, RevocationList revocationList,
                                   PlainText plainText1, PlainText plainText2) {
        this.scheme = scheme;
        this.clazz = scheme.getClass();
        this.openerKey = openerKey;
        this.issuerKey = issuerKey;
        this.groupMembershipList = groupMembershipList;
        this.revocationList = revocationList;
        this.plainText1 = plainText1;
        this.plainText2 = plainText2;
    }

    public GroupSignatureTestParam(Class<? extends GroupSignatureScheme> clazz) {
        this.clazz = clazz;
    }

    public Class<? extends GroupSignatureScheme> getClazz() {
        return clazz;
    }

    public GroupSignatureScheme getScheme() {
        return scheme;
    }

    public OpenerKey getOpenerKey() {
        return openerKey;
    }

    public IssuerKey getIssuerKey() {
        return issuerKey;
    }

    public GroupMembershipList getGroupMembershipList() {
        return groupMembershipList;
    }

    public RevocationList getRevocationList() {
        return revocationList;
    }

    public PlainText getPlainText1() {
        return plainText1;
    }

    public PlainText getPlainText2() {
        return plainText2;
    }
}
