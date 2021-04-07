package org.cryptimeleon.groupsig.common;

/**
 * Contains information about the result of executing
 * {@link GroupSignatureScheme#open(GroupSignature, OpenerKey, GroupMembershipList, RevocationList)}.
 * Specifically, the revealed member identity and, if supported by the scheme, a proof that the opening was done
 * correctly.
 */
public class OpenResult {

    /**
     * The opened identity.
     */
    protected Integer memberIdentity;

    /**
     * The proof that the opening was done correctly. May be null if the scheme does not support open proofs.
     */
    protected OpenProof openProof;

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
