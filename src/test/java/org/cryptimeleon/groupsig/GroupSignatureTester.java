package org.cryptimeleon.groupsig;

import org.cryptimeleon.craco.common.TestParameterProvider;
import org.cryptimeleon.craco.common.plaintexts.PlainText;
import org.cryptimeleon.groupsig.common.*;
import org.cryptimeleon.math.serialization.Representation;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.reflections.Reflections;

import java.lang.reflect.Modifier;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Testing class for {@link GroupSignatureScheme} implementations. Automatically collects such implementations
 * as well as testing parameters if they exist, and runs a set of tests on them.
 *
 * <p>Each scheme to test must offer a testing parameter provider class by implementing the
 * {@link TestParameterProvider} interface. These providers are processed automatically only if they
 * are contained in the {@code org.cryptimeleon.groupsig.org.cryptimeleon.groupsig.params} package.
 * If this is not possible, the {@link GroupSignatureTestParam} instance can be manually added to {@code paramsToTest}
 * in the {@link GroupSignatureTester#getGroupSignatureTestParams()} method below.
 *
 * <p>This class is organized into nested classes by the dependency of tested group signature algorithms on other
 * algorithms. The representation tests are an exception to this as they are all grouped together.
 *
 * <p>If you want to test methods outside of the {@link GroupSignatureScheme} interface, you will have to create a new
 * testing class. Extending this tester class seems to lead to double execution of the inherited tests.
 */
public class GroupSignatureTester {

    @ParameterizedTest
    @MethodSource("getGroupSignatureTestParams")
    public void testJoin(GroupSignatureTestParam param) {
        if (param.getScheme() == null) {
            fail("Scheme " + param.getClazz().getName() + " has no respective test parameters. Please implement" +
                    " a corresponding TestParameterProvider under org.cryptimeleon.groupsig.params");
        }
        System.out.println("Running join");
        MemberKey memberKey = join(param);
        MemberKey memberKey2 = join(param);
        assertNotNull(memberKey, "First resulting member key is null");
        assertNotNull(memberKey2, "Second resulting member key is null");
        assertNotEquals(memberKey, memberKey2, "Resulting member keys are the same");
        try {
            System.out.println("Retrieving GML entry for member with identity " + memberKey.getIdentity());
            param.getGroupMembershipList().get(memberKey.getIdentity());
        } catch (Exception e) {
            fail("Could not retrieve GML entry for first member key from group membership list because of " + e);
        }
        try {
            System.out.println("Retrieving GML entry for member with identity " + memberKey.getIdentity());
            param.getGroupMembershipList().get(memberKey2.getIdentity());
        } catch (Exception e) {
            fail("Could not retrieve GML entry for second member key from group membership list because of " + e);
        }
    }

    @Nested
    public class AfterJoin {

        @ParameterizedTest
        @MethodSource("org.cryptimeleon.groupsig.GroupSignatureTester#getGroupSignatureTestParams")
        public void testSignAndVerify(GroupSignatureTestParam param) {
            if (param.getScheme() == null) {
                fail("Scheme " + param.getClazz().getName() + " has no respective test parameters. Please implement" +
                        " a corresponding TestParameterProvider under org.cryptimeleon.groupsig.params");
            }
            System.out.println("Running join");
            MemberKey memberKey = join(param);
            if (memberKey == null) {
                System.out.println("Join failed. Member key is null. Skipping test");
                assumeFalse(true);
            }
            System.out.println("Running sign and verify");
            GroupSignature signature = param.getScheme().sign(param.getPlainText1(), memberKey);
            Assertions.assertTrue(param.getScheme().verify(
                    param.getPlainText1(), signature),
                    "Signature does not verify"
            );
        }

        @Nested
        public class AfterSign {

            @ParameterizedTest
            @MethodSource("org.cryptimeleon.groupsig.GroupSignatureTester#getGroupSignatureTestParams")
            public void testOpen(GroupSignatureTestParam param) {
                if (param.getScheme() == null) {
                    fail("Scheme " + param.getClazz().getName() + " has no respective test parameters. " +
                            "Please implement a corresponding TestParameterProvider " +
                            "under org.cryptimeleon.groupsig.params");
                }
                System.out.println("Running join and sign");
                MemberKey memberKey = join(param);
                if (memberKey == null) {
                    System.out.println("Join failed. Member key is null. Skipping test");
                    assumeFalse(true);
                }
                GroupSignature signature = param.getScheme().sign(param.getPlainText1(), memberKey);
                if (!param.getScheme().verify(param.getPlainText1(), signature)) {
                    System.out.println("Signing failed. Signature does not verify. Skipping test");
                    assumeFalse(true);
                }
                System.out.println("Running open");
                OpenResult openResult = param.getScheme().open(
                        signature, param.getOpenerKey(), param.getGroupMembershipList()
                );
                Integer identity = openResult.getMemberIdentity();
                assertEquals(memberKey.getIdentity(), identity, "Opened identity is incorrect");
            }

            @ParameterizedTest
            @MethodSource("org.cryptimeleon.groupsig.GroupSignatureTester#getGroupSignatureTestParams")
            public void testOpenVerify(GroupSignatureTestParam param) {
                if (param.getScheme() == null) {
                    fail("Scheme " + param.getClazz().getName() + " has no respective test parameters. " +
                            "Please implement a corresponding TestParameterProvider " +
                            "under org.cryptimeleon.groupsig.params");
                }
                System.out.println("Running join and sign");
                MemberKey memberKey = join(param);
                if (memberKey == null) {
                    System.out.println("Join failed. Member key is null. Skipping test");
                    assumeFalse(true);
                }
                GroupSignature signature = param.getScheme().sign(param.getPlainText1(), memberKey);
                if (!param.getScheme().verify(param.getPlainText1(), signature)) {
                    System.out.println("Signing failed. Signature does not verify. Skipping test");
                    assumeFalse(true);
                }
                System.out.println("Running open");
                OpenResult openResult = param.getScheme().open(
                        signature, param.getOpenerKey(), param.getGroupMembershipList()
                );
                Integer identity = openResult.getMemberIdentity();
                assumeTrue(memberKey.getIdentity().equals(identity), "Opened identity is incorrect");
                System.out.println("Running openVerify");
                Boolean successful;
                try {
                    successful = param.getScheme().openVerify(openResult, signature);
                } catch (UnsupportedOperationException e) {
                    System.out.println("OpenVerify not implemented. Skipping test");
                    return;
                }
                if (!successful) {
                    System.out.println("Test not successful. If you do not support " +
                            "openVerify, make sure that it throws an UnsupportedOperationException");
                }
                assertTrue(successful);
            }

            @ParameterizedTest
            @MethodSource("org.cryptimeleon.groupsig.GroupSignatureTester#getGroupSignatureTestParams")
            public void testClaimAndClaimVerify(GroupSignatureTestParam param) {
                if (param.getScheme() == null) {
                    fail("Scheme " + param.getClazz().getName() + " has no respective test parameters. " +
                            "Please implement a corresponding TestParameterProvider " +
                            "under org.cryptimeleon.groupsig.params");
                }
                System.out.println("Running join and sign");
                MemberKey memberKey = join(param);
                if (memberKey == null) {
                    System.out.println("Join failed. Member key is null. Skipping test");
                    assumeFalse(true);
                }
                GroupSignature signature = param.getScheme().sign(param.getPlainText1(), memberKey);
                if (!param.getScheme().verify(param.getPlainText1(), signature)) {
                    System.out.println("Signing failed. Signature does not verify. Skipping test");
                    assumeFalse(true);
                }
                System.out.println("Running claim and claimVerify");
                Boolean successful;
                try {
                    ClaimProof claimProof = param.getScheme().claim(memberKey, signature);
                    successful = param.getScheme().claimVerify(claimProof, signature);
                } catch (UnsupportedOperationException e) {
                    System.out.println("Claim/ClaimVerify not implemented. Skipping test");
                    return;
                }
                if (!successful) {
                    System.out.println("Test not successful. If you do not support " +
                            "claim/claimVerify, make sure that those methods throw an UnsupportedOperationException");
                }
                assertTrue(successful);
            }

            @ParameterizedTest
            @MethodSource("org.cryptimeleon.groupsig.GroupSignatureTester#getGroupSignatureTestParams")
            public void testRevealAndTrace(GroupSignatureTestParam param) {
                if (param.getScheme() == null) {
                    fail("Scheme " + param.getClazz().getName() + " has no respective test parameters. " +
                            "Please implement a corresponding TestParameterProvider " +
                            "under org.cryptimeleon.groupsig.params");
                }
                System.out.println("Running join and sign");
                MemberKey memberKey = join(param);
                if (memberKey == null) {
                    System.out.println("Join failed. Member key is null. Skipping test");
                    assumeFalse(true);
                }
                GroupSignature signature = param.getScheme().sign(param.getPlainText1(), memberKey);
                if (!param.getScheme().verify(param.getPlainText1(), signature)) {
                    System.out.println("Signing failed. Signature does not verify. Skipping test");
                    assumeFalse(true);
                }
                System.out.println("Running reveal and trace");
                Boolean successful;
                try {
                    param.getScheme().reveal(
                            param.getGroupMembershipList(), memberKey.getIdentity(), param.getRevocationList()
                    );
                    successful = param.getScheme().trace(
                            signature, param.getRevocationList(), param.getOpenerKey(), param.getGroupMembershipList());
                } catch (UnsupportedOperationException e) {
                    System.out.println("Reveal/Trace not implemented. Skipping test");
                    return;
                }
                if (!successful) {
                    System.out.println("Test not successful. If you do not support " +
                            "reveal/trace, make sure that those methods throw an UnsupportedOperationException");
                }
                assertTrue(successful);
            }

            @ParameterizedTest
            @MethodSource("org.cryptimeleon.groupsig.GroupSignatureTester#getGroupSignatureTestParams")
            public void testProveEqualityAndProveEqualityVerify(GroupSignatureTestParam param) {
                if (param.getScheme() == null) {
                    fail("Scheme " + param.getClazz().getName() + " has no respective test parameters. " +
                            "Please implement a corresponding TestParameterProvider " +
                            "under org.cryptimeleon.groupsig.params");
                }
                System.out.println("Running join and sign");
                MemberKey memberKey = join(param);
                if (memberKey == null) {
                    System.out.println("Join failed. Member key is null. Skipping test");
                    assumeFalse(true);
                }
                GroupSignature signature1 = param.getScheme().sign(param.getPlainText1(), memberKey);
                if (!param.getScheme().verify(param.getPlainText1(), signature1)) {
                    System.out.println("Signing failed. First signature does not verify. Skipping test");
                    assumeFalse(true);
                }
                GroupSignature signature2 = param.getScheme().sign(param.getPlainText1(), memberKey);
                if (!param.getScheme().verify(param.getPlainText1(), signature2)) {
                    System.out.println("Signing failed. Second signature does not verify. Skipping test");
                    assumeFalse(true);
                }
                List<GroupSignature> signatures = new LinkedList<>();
                signatures.add(signature1);
                signatures.add(signature2);
                System.out.println("Running proveEquality and proveEqualityVerify");
                boolean successful;
                try {
                    EqualityProof proof = param.getScheme().proveEquality(memberKey, signatures);
                    successful = param.getScheme().proveEqualityVerify(proof, signatures);
                } catch (UnsupportedOperationException e) {
                    System.out.println("ProveEquality/ProveEqualityVerify not supported. Skipping test");
                    return;
                }
                if (!successful) {
                    System.out.println("Test not successful. If you do not support " +
                            "proveEquality/proveEqualityVerify, make sure that those methods throw an " +
                            "UnsupportedOperationException");
                }
                assertTrue(successful);
            }
        }
    }

    @Nested
    class RepresentationTests {

        @ParameterizedTest
        @MethodSource("org.cryptimeleon.groupsig.GroupSignatureTester#getGroupSignatureTestParams")
        public void testGetOpenerKey(GroupSignatureTestParam param) {
            if (param.getScheme() == null) {
                fail("Scheme " + param.getClazz().getName() + " has no respective test parameters. " +
                        "Please implement a corresponding TestParameterProvider under " +
                        "org.cryptimeleon.groupsig.params");
            }
            OpenerKey reconstructedOpenerKey = param.getScheme().restoreOpenerKey(
                    param.getOpenerKey().getRepresentation()
            );
            Assertions.assertEquals(
                    param.getOpenerKey(), reconstructedOpenerKey,
                    "Reconstructed opener key does not match actual opener key"
            );
        }

        @ParameterizedTest
        @MethodSource("org.cryptimeleon.groupsig.GroupSignatureTester#getGroupSignatureTestParams")
        public void testGetIssuerKey(GroupSignatureTestParam param) {
            if (param.getScheme() == null) {
                fail("Scheme " + param.getClazz().getName() + " has no respective test parameters. " +
                        "Please implement a corresponding TestParameterProvider under " +
                        "org.cryptimeleon.groupsig.params");
            }
            IssuerKey reconstructedIssuerKey = param.getScheme().restoreIssuerKey(
                    param.getIssuerKey().getRepresentation()
            );
            Assertions.assertEquals(
                    param.getIssuerKey(), reconstructedIssuerKey,
                    "Reconstructed issuer key does not match actual issuer key");
        }

        @ParameterizedTest
        @MethodSource("org.cryptimeleon.groupsig.GroupSignatureTester#getGroupSignatureTestParams")
        public void testGetPlainText(GroupSignatureTestParam param) {
            if (param.getScheme() == null) {
                fail("Scheme " + param.getClazz().getName() + " has no respective test parameters. " +
                        "Please implement a corresponding TestParameterProvider under " +
                        "org.cryptimeleon.groupsig.params");
            }
            PlainText reconstructedPlainText = param.getScheme().restorePlainText(
                    param.getPlainText1().getRepresentation()
            );
            assertEquals(
                    param.getPlainText1(), reconstructedPlainText,
                    "Reconstructed plain text does not match actual plain text"
            );
        }

        @ParameterizedTest
        @MethodSource("org.cryptimeleon.groupsig.GroupSignatureTester#getGroupSignatureTestParams")
        public void testGetMemberKey(GroupSignatureTestParam param) {
            if (param.getScheme() == null) {
                fail("Scheme " + param.getClazz().getName() + " has no respective test parameters. " +
                        "Please implement a corresponding TestParameterProvider under " +
                        "org.cryptimeleon.groupsig.params");
            }
            System.out.println("Running join");
            MemberKey memberKey = join(param);
            if (memberKey == null) {
                System.out.println("Join failed. Member key is null. Skipping test");
                assumeFalse(true);
            }
            System.out.println("Testing representation");
            MemberKey reconstructuredMemberKey = param.getScheme().restoreMemberKey(
                    memberKey.getRepresentation()
            );
            assertEquals(
                    memberKey, reconstructuredMemberKey,
                    "Reconstructed member key does not match actual member key"
            );
        }

        @ParameterizedTest
        @MethodSource("org.cryptimeleon.groupsig.GroupSignatureTester#getGroupSignatureTestParams")
        public void testGetGmlEntry(GroupSignatureTestParam param) {
            if (param.getScheme() == null) {
                fail("Scheme " + param.getClazz().getName() + " has no respective test parameters. " +
                        "Please implement a corresponding TestParameterProvider under " +
                        "org.cryptimeleon.groupsig.params");
            }
            System.out.println("Running join");
            MemberKey memberKey = join(param);
            if (memberKey == null) {
                System.out.println("Join failed. Member key is null. Skipping test");
                assumeFalse(true);
            }
            System.out.println("Testing representation");
            GMLEntry gmlEntry = null;
            try {
                gmlEntry = param.getGroupMembershipList().get(memberKey.getIdentity());
            } catch (Exception e) {
                assumeTrue(false,
                        "GML entry for member key not retrievable from group membership list");
            }
            GMLEntry reconstructedGmlEntry = param.getScheme().restoreGmlEntry(gmlEntry.getRepresentation());
            assertEquals(
                    gmlEntry, reconstructedGmlEntry,
                    "Reconstructed GML entry does not match actual GML entry"
            );
        }

        @ParameterizedTest
        @MethodSource("org.cryptimeleon.groupsig.GroupSignatureTester#getGroupSignatureTestParams")
        public void testGetGroupMembershipList(GroupSignatureTestParam param) {
            if (param.getScheme() == null) {
                fail("Scheme " + param.getClazz().getName() + " has no respective test parameters. " +
                        "Please implement a corresponding TestParameterProvider under " +
                        "org.cryptimeleon.groupsig.params");
            }
            System.out.println("Running join");
            MemberKey memberKey = join(param);
            if (memberKey == null) {
                System.out.println("Join failed. Member key is null. Skipping test");
                assumeFalse(true);
            }
            System.out.println("Testing representation");
            GroupMembershipList reconstructedGml = param.getScheme().restoreGroupMembershipList(
                    param.getGroupMembershipList().getRepresentation()
            );
            Assertions.assertEquals(
                    param.getGroupMembershipList(), reconstructedGml,
                    "Reconstructed GML does not match actual GML"
            );
        }

        @ParameterizedTest
        @MethodSource("org.cryptimeleon.groupsig.GroupSignatureTester#getGroupSignatureTestParams")
        public void testGetRevocationListEntry(GroupSignatureTestParam param) {
            if (param.getScheme() == null) {
                fail("Scheme " + param.getClazz().getName() + " has no respective test parameters. " +
                        "Please implement a corresponding TestParameterProvider under " +
                        "org.cryptimeleon.groupsig.params");
            }
            System.out.println("Running join");
            MemberKey memberKey = join(param);
            if (memberKey == null) {
                System.out.println("Join failed. Member key is null. Skipping test");
                assumeFalse(true);
            }
            System.out.println("Running reveal");
            try {
                param.getScheme().reveal(
                        param.getGroupMembershipList(), memberKey.getIdentity(), param.getRevocationList()
                );
            } catch (UnsupportedOperationException e) {
                System.out.println("Reveal not supported by scheme. Skipping test assertions");
                return;
            }
            RevocationListEntry revEntry = null;
            try {
                revEntry = param.getRevocationList().get(memberKey.getIdentity());
            } catch (Exception e) {
                System.out.println(
                        "Revocation list entry for member key not retrievable from revocation list. "
                                + "Skipping test"
                );
                assumeTrue(false);
            }
            System.out.println("Testing representation");
            Assertions.assertEquals(
                    revEntry, param.getScheme().restoreRevocationListEntry(revEntry.getRepresentation()),
                    "Reconstructed revocation list entry does not match actual revocation list entry"
            );
        }

        @ParameterizedTest
        @MethodSource("org.cryptimeleon.groupsig.GroupSignatureTester#getGroupSignatureTestParams")
        public void testGetRevocationList(GroupSignatureTestParam param) {
            if (param.getScheme() == null) {
                fail("Scheme " + param.getClazz().getName() + " has no respective test parameters. " +
                        "Please implement a corresponding TestParameterProvider under " +
                        "org.cryptimeleon.groupsig.params");
            }
            System.out.println("Running join");
            MemberKey memberKey = join(param);
            if (memberKey == null) {
                System.out.println("Join failed. Member key is null. Skipping test");
                assumeFalse(true);
            }
            System.out.println("Running reveal");
            try {
                param.getScheme().reveal(
                        param.getGroupMembershipList(), memberKey.getIdentity(), param.getRevocationList()
                );
            } catch (UnsupportedOperationException e) {
                System.out.println("Reveal not supported by scheme. Skipping test assertions");
                return;
            }
            System.out.println("Testing representation");
            Assertions.assertEquals(
                    param.getRevocationList(),
                    param.getScheme().restoreRevocationList(param.getRevocationList().getRepresentation()),
                    "Reconstructed revocation list does not match actual revocation list"
            );
        }

        @ParameterizedTest
        @MethodSource("org.cryptimeleon.groupsig.GroupSignatureTester#getGroupSignatureTestParams")
        public void testGetOpenProof(GroupSignatureTestParam param) {
            if (param.getScheme() == null) {
                fail("Scheme " + param.getClazz().getName() + " has no respective test parameters. " +
                        "Please implement a corresponding TestParameterProvider under " +
                        "org.cryptimeleon.groupsig.params");
            }
            System.out.println("Running join and sign");
            MemberKey memberKey = join(param);
            if (memberKey == null) {
                System.out.println("Join failed. Member key is null. Skipping test");
                assumeFalse(true);
            }
            GroupSignature signature = param.getScheme().sign(param.getPlainText1(), memberKey);
            if (!param.getScheme().verify(param.getPlainText1(), signature)) {
                System.out.println("Signing failed. Signature does not verify. Skipping test");
                assumeFalse(true);
            }
            System.out.println("Running open");
            OpenResult openResult = param.getScheme().open(
                    signature, param.getOpenerKey(), param.getGroupMembershipList()
            );
            if (openResult.getOpenProof() == null) {
                System.out.println("No open proof. Skipping test");
                assumeFalse(true);
            }
            if (!param.getScheme().openVerify(openResult, signature)) {
                System.out.println("Open failed. Proof does not verify. Skipping test");
                assumeFalse(true);
            }
            System.out.println("Testing representation");
            Assertions.assertEquals(
                    openResult.getOpenProof(),
                    param.getScheme().restoreOpenProof(openResult.getOpenProof().getRepresentation()),
                    "Reconstructed open proof does not match actual open proof"
            );
        }

        @ParameterizedTest
        @MethodSource("org.cryptimeleon.groupsig.GroupSignatureTester#getGroupSignatureTestParams")
        public void testGetClaimProof(GroupSignatureTestParam param) {
            if (param.getScheme() == null) {
                fail("Scheme " + param.getClazz().getName() + " has no respective test parameters. " +
                        "Please implement a corresponding TestParameterProvider under " +
                        "org.cryptimeleon.groupsig.params");
            }
            System.out.println("Running join and sign");
            MemberKey memberKey = join(param);
            if (memberKey == null) {
                System.out.println("Join failed. Member key is null. Skipping test");
                assumeFalse(true);
            }
            GroupSignature signature = param.getScheme().sign(param.getPlainText1(), memberKey);
            if (!param.getScheme().verify(param.getPlainText1(), signature)) {
                System.out.println("Signing failed. Signature does not verify. Skipping test");
                assumeFalse(true);
            }
            System.out.println("Running claim");
            ClaimProof claimProof;
            try {
                claimProof = param.getScheme().claim(memberKey, signature);
                assertNotNull(claimProof, "Claim proof is null. Either implement claim or throw an " +
                        "UnsupportedOperationException to indicate that you do not support claim.");
            } catch (UnsupportedOperationException e) {
                System.out.println("Claim not supported by scheme. Skipping test assertions");
                return;
            }
            if (!param.getScheme().claimVerify(claimProof, signature)) {
                System.out.println("Claim failed. Proof does not verify. Skipping test");
                assumeFalse(true);
            }
            System.out.println("Testing representation");
            Assertions.assertEquals(
                    claimProof,
                    signature.restoreClaimProof(claimProof.getRepresentation()),
                    "Reconstructed claim proof does not match actual claim proof"
            );
        }

        @ParameterizedTest
        @MethodSource("org.cryptimeleon.groupsig.GroupSignatureTester#getGroupSignatureTestParams")
        public void testGetEqualityProof(GroupSignatureTestParam param) {
            if (param.getScheme() == null) {
                fail("Scheme " + param.getClazz().getName() + " has no respective test parameters. " +
                        "Please implement a corresponding TestParameterProvider under " +
                        "org.cryptimeleon.groupsig.params");
            }
            System.out.println("Running join and sign");
            MemberKey memberKey = join(param);
            if (memberKey == null) {
                System.out.println("Join failed. Member key is null. Skipping test");
                assumeFalse(true);
            }
            GroupSignature signature1 = param.getScheme().sign(param.getPlainText1(), memberKey);
            if (!param.getScheme().verify(param.getPlainText1(), signature1)) {
                System.out.println("Signing failed. First signature does not verify. Skipping test");
                assumeFalse(true);
            }
            GroupSignature signature2 = param.getScheme().sign(param.getPlainText1(), memberKey);
            if (!param.getScheme().verify(param.getPlainText1(), signature2)) {
                System.out.println("Signing failed. Second signature does not verify. Skipping test");
                assumeFalse(true);
            }
            List<GroupSignature> signatures = new LinkedList<>();
            signatures.add(signature1);
            signatures.add(signature2);
            System.out.println("Running proveEquality and proveEqualityVerify");
            EqualityProof proof;
            try {
                proof = param.getScheme().proveEquality(memberKey, signatures);
                assertNotNull(proof, "Equality proof is null. Either implement proveEquality or throw an "
                        + "UnsupportedOperationException to indicate that you do not support proveEquality.");
            } catch (UnsupportedOperationException e) {
                System.out.println("ProveEquality not supported by scheme. Skipping test assertions");
                return;
            }
            if (!param.getScheme().proveEqualityVerify(proof, signatures)) {
                System.out.println("ProveEquality failed. Proof does not verify. Skipping test");
                assumeFalse(true);
            }
            System.out.println("Testing representation");
            Assertions.assertEquals(
                    proof,
                    param.getScheme().restoreEqualityProof(proof.getRepresentation()),
                    "Reconstructed equality proof does not match actual equality proof"
            );
        }
    }

    public static Stream<GroupSignatureTestParam> getGroupSignatureTestParams() {
        // Get all classes that implement GroupSignatureScheme in Craco
        Reflections reflectionCraco = new Reflections("org.cryptimeleon.groupsig");
        Set<Class<? extends GroupSignatureScheme>> schemeClasses =
                reflectionCraco.getSubTypesOf(GroupSignatureScheme.class);
        // Get all classes that provide parameters for the group signature scheme tests
        Reflections reflectionParams = new Reflections("org.cryptimeleon.groupsig.params");
        Set<Class<? extends TestParameterProvider>> paramProviderClasses =
                reflectionParams.getSubTypesOf(TestParameterProvider.class);

        // Fill the list of parameters used in test with the found parameters
        List<GroupSignatureTestParam> paramsToTest = new LinkedList<>();
        for (Class<? extends TestParameterProvider> providerClass : paramProviderClasses) {
            try {
                Object params = providerClass.newInstance().get();
                paramsToTest.add((GroupSignatureTestParam) params);
            } catch (InstantiationException | IllegalAccessException e) {
                System.out.println("Not able to instantiate GroupSignatureTestParameterProvider " + providerClass
                                + " because of " + e);
            } catch (ClassCastException e) {
                System.out.println("Not able to cast test params provided by " + providerClass
                        + " to GroupSignatureTestParam");
            }
        }

        // Remove all schemes that have parameters provided from the list of classes
        for (GroupSignatureTestParam param : paramsToTest) {
            schemeClasses.remove(param.getScheme().getClass());
        }

        // Classes without provided parameters have empty org.cryptimeleon.groupsig.params that will force an error in the test
        for (Class<? extends  GroupSignatureScheme> clazz : schemeClasses) {
            if (!clazz.isInterface() && !Modifier.isAbstract(clazz.getModifiers())) {
                paramsToTest.add(new GroupSignatureTestParam(clazz));
            }
        }
        return paramsToTest.stream();
    }

    static MemberKey join(GroupSignatureTestParam param) {
        LinkedBlockingQueue<Representation> memberToIssuer = new LinkedBlockingQueue<>();
        LinkedBlockingQueue<Representation> issuerToMember = new LinkedBlockingQueue<>();
        ExecutorService es = Executors.newFixedThreadPool(2);
        Future<MemberKey> memberResult = es.submit(() -> param.getScheme().joinMember(issuerToMember, memberToIssuer));
        Future<?> issuerResult = es.submit(
                () -> {
                    try {
                        param.getScheme().joinIssuer(param.getIssuerKey(), param.getGroupMembershipList(), memberToIssuer,
                                issuerToMember);
                    } catch (InterruptedException e) {
                        System.out.println("One of the queues timed out waiting for operation");
                        e.printStackTrace();
                    }
                }
        );
        MemberKey memberKey = null;
        try {
            memberKey = memberResult.get();
            issuerResult.get();
        } catch (Exception e) {
            fail(e);
        }
        return memberKey;
    }
}
