package de.upb.crypto.groupsig.common;

import de.upb.crypto.groupsig.interfaces.*;

/**
 * Contains information about the result of executing
 * {@link GroupSignatureScheme#open(GroupSignature, OpenerKey, GroupMembershipList, RevocationList)}.
 * Specifically, the revealed member identity and, if supported by the scheme, a proof that the opening was done
 * correctly.
 *
 * @author Raphael Heitjohann
 */
public class OpenResult {

    private Integer memberIdentity;
    private OpenProof openProof;

    public OpenResult(Integer memberIdentity, OpenProof openProof) {
        this.memberIdentity = memberIdentity;
        this.openProof = openProof;
    }

    public OpenResult(Integer memberIdentity) {
        this(memberIdentity, null);
    }

    public Integer getMemberIdentity() {
        return memberIdentity;
    }

    public OpenProof getOpenProof() {
        return openProof;
    }
}
