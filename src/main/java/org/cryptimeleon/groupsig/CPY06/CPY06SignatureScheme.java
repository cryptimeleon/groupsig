package org.cryptimeleon.groupsig.CPY06;

import org.cryptimeleon.craco.common.ByteArrayImplementation;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.groupsig.CPY06.issuing_protocol.CPY06IssuerCommonInput;
import org.cryptimeleon.groupsig.CPY06.issuing_protocol.CPY06IssuingProtocol;
import org.cryptimeleon.groupsig.CPY06.issuing_protocol.CPY06IssuingProtocolIssuerInstance;
import org.cryptimeleon.groupsig.CPY06.issuing_protocol.CPY06IssuingProtocolUserInstance;
import org.cryptimeleon.groupsig.common.*;
import org.cryptimeleon.math.hash.ByteAccumulator;
import org.cryptimeleon.math.hash.impl.ByteArrayAccumulator;
import org.cryptimeleon.math.serialization.Representation;
import org.cryptimeleon.math.serialization.annotations.ReprUtil;
import org.cryptimeleon.math.serialization.annotations.Represented;
import org.cryptimeleon.math.structures.groups.GroupElement;
import org.cryptimeleon.math.structures.groups.elliptic.BilinearMap;
import org.cryptimeleon.math.structures.rings.zn.Zn;
import org.cryptimeleon.math.structures.rings.zn.Zp;

import java.util.Collection;
import java.util.Objects;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Implements the traceable group signature scheme from [CPY06].
 *
 * [CPY06] Choi, Seung & Park, Kunsoo & Yung, Moti. (2006).
 * Short Traceable Signatures Based on Bilinear Pairings.
 */
public class CPY06SignatureScheme implements GroupSignatureScheme {

    @Represented
    private CPY06PublicParameters pp;

    public CPY06SignatureScheme(CPY06PublicParameters pp) {
        this.pp = pp;
    }

    public CPY06SignatureScheme(Representation repr) {
        new ReprUtil(this).deserialize(repr);
    }

    @Override
    public MemberKey joinMember(BlockingQueue<Representation> received, BlockingQueue<Representation> sent)
            throws InterruptedException {
        CPY06IssuingProtocol protocol = new CPY06IssuingProtocol();
        // No secret input required for user here
        CPY06IssuingProtocolUserInstance userInstance =
                (CPY06IssuingProtocolUserInstance) protocol.instantiateUser(pp, null);
        // user starts
        sent.offer(userInstance.nextMessage(null));
        while (!userInstance.hasTerminated()) {
            Representation nextReceived = received.poll(5, TimeUnit.SECONDS);
            Representation nextSent = userInstance.nextMessage(nextReceived);
            // last one we don't send anything (just verify cert), so need to check for null
            if (nextSent != null) {
                sent.offer(nextSent , 5, TimeUnit.SECONDS);
            }
        }
        return userInstance.getResultingMemberKey();
    }

    @Override
    public void joinIssuer(IssuerKey issuerKey, GroupMembershipList gml, BlockingQueue<Representation> received,
                           BlockingQueue<Representation> sent) throws InterruptedException {
        CPY06IssuingProtocol protocol = new CPY06IssuingProtocol();
        CPY06IssuerCommonInput commonInput = new CPY06IssuerCommonInput(pp, gml.getNextNewUserId());
        CPY06IssuingProtocolIssuerInstance issuerInstance =
                (CPY06IssuingProtocolIssuerInstance) protocol.instantiateIssuer(commonInput, (CPY06IssuerKey) issuerKey);
        while (!issuerInstance.hasTerminated()) {
            Representation nextReceived = received.poll(5, TimeUnit.SECONDS);
            sent.offer(issuerInstance.nextMessage(nextReceived), 5, TimeUnit.SECONDS);
        }
        gml.put(issuerInstance.getGroupMembershipListEntry());
    }

    @Override
    public GroupSignature sign(PlainText message, MemberKey memberKey) {
        if (!(memberKey instanceof CPY06MemberKey)) {
            throw new IllegalArgumentException("Given signing key " + memberKey + " is not a CPY06MemberKey");
        }
        if (!(message instanceof ByteArrayImplementation)) {
            throw new IllegalArgumentException("Given message " + message + " is not a ByteArrayImplementation");
        }
        // Compute T_1, ..., T_5
        CPY06MemberKey cpy06MemberKey = (CPY06MemberKey) memberKey;

        Zp zp = pp.getZp();
        Zp.ZpElement r1 = zp.getUniformlyRandomElement();
        Zp.ZpElement r2 = zp.getUniformlyRandomElement();
        Zp.ZpElement r3 = zp.getUniformlyRandomElement();
        Zp.ZpElement d1 = cpy06MemberKey.getT().mul(r1);
        Zp.ZpElement d2 = cpy06MemberKey.getT().mul(r2);

        BilinearMap e = pp.getBilGroup().getBilinearMap();

        GroupElement T1 = pp.getX().pow(r1).compute();
        GroupElement T2 = pp.getY().pow(r2).compute();
        // T_3 = A + (r_1 + r_2) * Z
        GroupElement T3 = cpy06MemberKey.getA().op(pp.getZ().pow(r1.add(r2))).compute();
        GroupElement T4 = pp.getW().pow(r3).compute();
        // T_5 = e(P_1, T_4)^x
        GroupElement T5 = e.apply(
                pp.getP1(), T4
        ).pow(cpy06MemberKey.getX()).compute();

        // Compute B_1, ..., B_6
        Zp.ZpElement br1 = zp.getUniformlyRandomElement();
        Zp.ZpElement br2 = zp.getUniformlyRandomElement();
        Zp.ZpElement bd1 = zp.getUniformlyRandomElement();
        Zp.ZpElement bd2 = zp.getUniformlyRandomElement();
        Zp.ZpElement bt = zp.getUniformlyRandomElement();
        Zp.ZpElement bx = zp.getUniformlyRandomElement();

        GroupElement B1 = pp.getX().pow(br1).compute();
        GroupElement B2 = pp.getY().pow(br2).compute();
        // B_3 = b_t * T_1 - b_{d_1} * X
        GroupElement B3 = T1.pow(bt).op(pp.getX().pow(bd1).inv()).compute();
        // B_4 = b_t * T_2 - b_{d_2} * Y
        GroupElement B4 = T2.pow(bt).op(pp.getY().pow(bd2).inv()).compute();
        // B_5 = e(P_1, T_4)^{b_x}
        GroupElement B5 = e.apply(
                pp.getP1(), T4
        ).pow(bx).compute();
        // B_6 = e(T_3, P_2)^{b_t} * e(Z, P_2)^{-b_{d_1}-b_{d_2}} * e(Z, R)^{-b_{r_1}-b_{r_2}} * e(P_1, P_2)^{-b_x}
        GroupElement B6 = e.apply(T3, pp.getP2()).pow(bt)
                .op(e.apply(pp.getZ(), pp.getP2()).pow(bd1.add(bd2)).inv())
                .op(e.apply(pp.getZ(), pp.getR()).pow(br1.add(br2)).inv())
                .op(e.apply(pp.getP1(), pp.getP2()).pow(bx).inv()).compute();

        // c = H(m, T_1, ..., T_5, B_1, ..., B_6)
        Zp.ZpElement c = hash(message, T1, T2, T3, T4, T5, B1, B2, B3, B4, B5, B6);

        Zp.ZpElement sr1 = br1.add(c.mul(r1));
        Zp.ZpElement sr2 = br2.add(c.mul(r2));
        Zp.ZpElement sd1 = bd1.add(c.mul(d1));
        Zp.ZpElement sd2 = bd2.add(c.mul(d2));
        Zp.ZpElement sx = bx.add(c.mul(cpy06MemberKey.getX()));
        Zp.ZpElement st = bt.add(c.mul(cpy06MemberKey.getT()));

        return new CPY06Signature(T1, T2, T3, T4, T5, c, sr1, sr2, sd1, sd2, sx, st);
    }

    @Override
    public Boolean verify(PlainText message, GroupSignature signature, RevocationList revocationList) {
        if (!(signature instanceof CPY06Signature)) {
            throw new IllegalArgumentException("Given signature " + signature + " is not a CPY06Signature");
        }
        if (!(message instanceof ByteArrayImplementation)) {
            throw new IllegalArgumentException("Given message " + message + " is not a ByteArrayImplementation");
        }
        CPY06Signature cpy06Signature = (CPY06Signature) signature;

        // Compute B_1, ..., B_6
        Zp.ZpElement c = cpy06Signature.getC();
        Zp.ZpElement sr1 = cpy06Signature.getSr1();
        Zp.ZpElement sr2 = cpy06Signature.getSr2();
        Zp.ZpElement sd1 = cpy06Signature.getSd1();
        Zp.ZpElement sd2 = cpy06Signature.getSd2();
        Zp.ZpElement sx = cpy06Signature.getSx();
        Zp.ZpElement st = cpy06Signature.getSt();
        BilinearMap e = pp.getBilGroup().getBilinearMap();
        // B_1 = s_{r_1} * X - c * T_1
        GroupElement B1 = pp.getX().pow(sr1).op(cpy06Signature.getT1().pow(c).inv()).compute();
        // B_2 = s_{r_2} * Y - c * T_2
        GroupElement B2 = pp.getY().pow(sr2).op(cpy06Signature.getT2().pow(c).inv()).compute();
        // B_3 = s_t * T_1 - s_{d_1} * X
        GroupElement B3 = cpy06Signature.getT1().pow(st).op(pp.getX().pow(sd1).inv()).compute();
        // B_4 = s_t * T_2 - s_{d_2} * Y
        GroupElement B4 = cpy06Signature.getT2().pow(st).op(pp.getY().pow(sd2).inv()).compute();
        // B_5 = e(P_1, T_4)^{s_x} * T_4^{-c}
        GroupElement B5 = e.apply(pp.getP1(), cpy06Signature.getT4()).pow(sx)
                .op(cpy06Signature.getT5().pow(c).inv()).compute();
        // B_6 = e(T_3, P_2)^{s_t} * e(Z, P_2}^{-s_{d_1}-s_{d_2}} * e(Z, R)^{-s_{r_1}-s_{r_2}} * e(P_1, P_2)^{-s_x}
        //       * (e(T_3, R) / e(Q, P_2))^c
        GroupElement B6 = e.apply(cpy06Signature.getT3(), pp.getP2()).pow(st)
                .op(e.apply(pp.getZ(), pp.getP2()).pow(sd1.add(sd2)).inv())
                .op(e.apply(pp.getZ(), pp.getR()).pow(sr1.add(sr2)).inv())
                .op(e.apply(pp.getP1(), pp.getP2()).pow(sx).inv())
                .op(e.apply(cpy06Signature.getT3(), pp.getR()).pow(c))
                .op(e.apply(pp.getQ(), pp.getP2()).pow(c).inv()).compute();

        // c' = H(m, T_1, ..., T_5, B_1, ..., B_6)
        Zp.ZpElement cPrime = hash(message, cpy06Signature.getT1(), cpy06Signature.getT2(), cpy06Signature.getT3(),
                cpy06Signature.getT4(), cpy06Signature.getT5(), B1, B2, B3, B4, B5, B6);

        return c.equals(cPrime);
    }

    @Override
    public ClaimProof claim(MemberKey memberKey, GroupSignature signature) {
        if (!(memberKey instanceof CPY06MemberKey)) {
            throw new IllegalArgumentException("Given signing key " + memberKey + " is not a CPY06MemberKey");
        }
        if (!(signature instanceof CPY06Signature)) {
            throw new IllegalArgumentException("Given signature " + signature + " is not a CPY06Signature");
        }
        CPY06MemberKey cpy06MemberKey = (CPY06MemberKey) memberKey;
        CPY06Signature cpy06Signature = (CPY06Signature) signature;

        // TODO (rh): Generate a proof of knowledge of the value x which satisfies e(P_1, T_4)^x = T_5
        //  This can be done via Schnorr.
        return null;
    }

    @Override
    public Boolean claimVerify(ClaimProof proof, GroupSignature signature) {
        // TODO (rh): Verify the proof
        return false;
    }

    @Override
    public OpenResult open(GroupSignature signature, OpenerKey openerKey, GroupMembershipList gml,
                           RevocationList revocationList) {
        if (!(signature instanceof CPY06Signature)) {
            throw new IllegalArgumentException("Given signature " + signature + " is not a CPY06Signature");
        }
        if (!(openerKey instanceof CPY06OpenerKey)) {
            throw new IllegalArgumentException("Given opener key " + openerKey + " is not a CPY06OpenerKey");
        }
        if (!(gml instanceof CPY06GroupMembershipList)) {
            throw new IllegalArgumentException("Given group membership list " + gml
                    + " is not a CPY06GroupMembershipList");
        }
        CPY06Signature cpy06Signature = (CPY06Signature) signature;
        CPY06ManagerKey cpy06ManagerKey = (CPY06OpenerKey) openerKey;
        CPY06GroupMembershipList cpy06GroupMembershipList = (CPY06GroupMembershipList) gml;

        // A = T_3 - (zeta_1 * T_1 + zeta_2 * T_2)
        GroupElement zeta1T1Pluszeta2T2 = cpy06Signature.getT1().pow(cpy06ManagerKey.getZeta1())
                .op(cpy06Signature.getT2().pow(cpy06ManagerKey.getZeta2()));
        GroupElement A = cpy06Signature.getT3().op(zeta1T1Pluszeta2T2.inv());
        return new OpenResult(cpy06GroupMembershipList.findUserIdFor(A));
    }

    @Override
    public Boolean openVerify(Integer memberIdentity, OpenProof openProof, GroupSignature signature) {
        throw new UnsupportedOperationException("openVerify does not exist for this scheme.");
    }

    @Override
    public void reveal(GroupMembershipList gml, Integer memberIdentity, RevocationList revocationList) {
        if (!(gml instanceof CPY06GroupMembershipList)) {
            throw new IllegalArgumentException("Given group membership list " + gml
                    + " is not a CPY06GroupMembershipList");
        }
        if (!(revocationList instanceof CPY06RevocationList)) {
            throw new IllegalArgumentException("Given revocation list " + revocationList
                    + " is not a CPY06RevocationList");
        }
        CPY06GroupMembershipList cpy06GroupMembershipList = (CPY06GroupMembershipList) gml;
        CPY06RevocationList cpy06RevocationList = (CPY06RevocationList) revocationList;

        cpy06RevocationList.put(new CPY06RevocationListEntry(
                memberIdentity, cpy06GroupMembershipList.get(memberIdentity).getC()
        ));
    }

    @Override
    public Boolean trace(GroupSignature signature, RevocationList revocationList, OpenerKey openerKey,
                         GroupMembershipList gml) {
        if (!(signature instanceof CPY06Signature)) {
            throw new IllegalArgumentException("Given signature " + signature + " is not a CPY06Signature");
        }
        if (!(revocationList instanceof CPY06RevocationList)) {
            throw new IllegalArgumentException("Given revocation list " + revocationList
                    + " is not a CPY06RevocationList");
        }
        CPY06Signature cpy06Signature = (CPY06Signature) signature;
        CPY06RevocationList cpy06RevocationList = (CPY06RevocationList) revocationList;

        for (CPY06RevocationListEntry val : cpy06RevocationList.getValues()) {
            boolean matches = pp.getBilGroup().getBilinearMap()
                    .apply(val.getC(), cpy06Signature.getT4())
                    .equals(cpy06Signature.getT5());
            if (matches) {
                return true;
            }
        }
        return false;
    }

    @Override
    public EqualityProof proveEquality(MemberKey memberKey, Collection<GroupSignature> signatures) {
        throw new UnsupportedOperationException("proveEquality does not exist for this scheme.");
    }

    @Override
    public Boolean proveEqualityVerify(EqualityProof equalityProof, Collection<GroupSignature> signatures) {
        throw new UnsupportedOperationException("proveEqualityVerify does not exist for this scheme.");
    }

    public CPY06PublicParameters getPp() {
        return pp;
    }

    @Override
    public Representation getRepresentation() {
        return ReprUtil.serialize(this);
    }

    @Override
    public MemberKey restoreMemberKey(Representation repr) {
        return new CPY06MemberKey(repr, pp.getBilGroup().getG1(), pp.getZp());
    }

    @Override
    public OpenerKey restoreOpenerKey(Representation repr) {
        return new CPY06OpenerKey(repr, pp.getZp());
    }

    @Override
    public IssuerKey restoreIssuerKey(Representation repr) {
        return new CPY06IssuerKey(repr, pp.getZp());
    }

    @Override
    public PlainText restorePlainText(Representation repr) {
        return new ByteArrayImplementation(repr);
    }

    @Override
    public GroupSignature restoreSignature(Representation repr) {
        return new CPY06Signature(repr, pp.getBilGroup());
    }

    @Override
    public GMLEntry restoreGmlEntry(Representation repr) {
        return new CPY06GMLEntry(repr, pp.getBilGroup().getG1(), pp.getZp());
    }

    @Override
    public GroupMembershipList restoreGroupMembershipList(Representation repr) {
        return new CPY06GroupMembershipList(repr, this);
    }

    @Override
    public RevocationList restoreRevocationList(Representation repr) {
        return new CPY06RevocationList(repr, this);
    }

    @Override
    public RevocationListEntry restoreRevocationListEntry(Representation repr) {
        return new CPY06RevocationListEntry(repr, pp.getBilGroup().getG1());
    }

    @Override
    public OpenProof restoreOpenProof(Representation repr) {
        throw new UnsupportedOperationException("This scheme does not support open proofs");
    }

    @Override
    public ClaimProof restoreClaimProof(Representation repr) {
        throw new UnsupportedOperationException("This scheme does not support claim proofs");
    }

    @Override
    public EqualityProof restoreEqualityProof(Representation repr) {
        throw new UnsupportedOperationException("This scheme does not support equality proofs");
    }

    @Override
    public PlainText mapToPlaintext(byte[] bytes) {
        return new ByteArrayImplementation(bytes);
    }

    @Override
    public int getMaxNumberOfBytesForMapToPlaintext() {
        return Integer.MAX_VALUE;
    }

    @Override
    public int hashCode() {
        return pp.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        CPY06SignatureScheme other = (CPY06SignatureScheme) obj;
        return Objects.equals(pp, other.pp);
    }

    private Zp.ZpElement hash(PlainText message, GroupElement T1, GroupElement T2, GroupElement T3, GroupElement T4,
                    GroupElement T5, GroupElement B1, GroupElement B2, GroupElement B3, GroupElement B4,
                    GroupElement B5, GroupElement B6) {
        ByteAccumulator accumulator = new ByteArrayAccumulator();
        accumulator.append(message.getUniqueByteRepresentation());
        accumulator.append(T1.getUniqueByteRepresentation());
        accumulator.append(T2.getUniqueByteRepresentation());
        accumulator.append(T3.getUniqueByteRepresentation());
        accumulator.append(T4.getUniqueByteRepresentation());
        accumulator.append(T5.getUniqueByteRepresentation());
        accumulator.append(B1.getUniqueByteRepresentation());
        accumulator.append(B2.getUniqueByteRepresentation());
        accumulator.append(B3.getUniqueByteRepresentation());
        accumulator.append(B4.getUniqueByteRepresentation());
        accumulator.append(B5.getUniqueByteRepresentation());
        accumulator.append(B6.getUniqueByteRepresentation());
        return pp.getHashFunction().hash(accumulator.extractBytes());
    }
}
