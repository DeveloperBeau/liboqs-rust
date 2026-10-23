//! Tests of the replicated known-answer program of the stateful schemes on a small scheme whose
//! output the test can follow by hand. The parity tests run the same program on the C schemes
//! and compare the digests with the digests of liboqs.

use OQSNativeAlgorithmTests::StatefulKnownAnswerTest;
use OQSNativeDomain::{KeyStatePersisting, RandomGenerating, StatefulSigning};
use OQSNativeEntities::{KeyPair, OQSError, SecretBytes, StatefulSignatureDescription};
use OQSNativeSHA2::SHA256;

/// The seed and the message of the response file of `XMSS-SHA2_10_256` of liboqs: the NIST
/// known-answer generator of the seed gives the message.
const responseSeed: &str = "1840C60AD9F35C900372EF38D08671A74353C965C3C5DE0668C9C3E5CF3926304322530FD9681CF3A9C71FD633D60C66";
const responseMessage: &str = "B338DD755D5618C464AB331F14DE3DD4A358BBA00D28FB35236741E902F7B248CE";

/// How the small scheme goes wrong, so that each failure path of the program runs.
#[derive(Clone, Copy, PartialEq)]
enum Fault {
    none,
    signingFails,
    shortSignature,
    rejectsEverySignature,
    countFails,
}

const xmssDescription: StatefulSignatureDescription = StatefulSignatureDescription {
    objectIdentifier: 1,
    name: "XMSS-Test",
    algorithmVersion: "test",
    isEUFCMASecure: true,
    isSUFCMASecure: false,
    publicKeyLength: 2,
    secretKeyLength: 4,
    signatureLength: 8,
};

const lmsDescription: StatefulSignatureDescription = StatefulSignatureDescription {
    name: "LMS_Test",
    ..xmssDescription
};

/// A scheme whose secret key is the big-endian index of the next signature, and whose
/// signature is that index followed by the first four bytes of the message. The public key is
/// `AB CD`, and a key makes 16 signatures.
struct IndexScheme {
    description: &'static StatefulSignatureDescription,
    fault: Fault,
}

impl StatefulSigning for IndexScheme {
    fn description(&self) -> &'static StatefulSignatureDescription {
        self.description
    }

    fn generateKeyPair(&self, _: &mut dyn RandomGenerating) -> Result<KeyPair, OQSError> {
        Err(OQSError::operationFailed)
    }

    fn sign(
        &self,
        message: &[u8],
        secretKey: &mut SecretBytes,
        persisting: &mut dyn KeyStatePersisting,
    ) -> Result<Vec<u8>, OQSError> {
        if self.fault == Fault::signingFails {
            return Err(OQSError::keyExhausted);
        }
        let index = u32::from_be_bytes(secretKey.bytes().try_into().expect("4 bytes"));
        let mut signature = index.to_be_bytes().to_vec();
        signature.extend_from_slice(&message[..4]);
        if self.fault == Fault::shortSignature {
            signature.pop();
        }
        *secretKey = SecretBytes::new((index + 1).to_be_bytes().to_vec());
        self.releaseSignature(signature, secretKey.bytes(), persisting)
    }

    fn isValidSignature(&self, signature: &[u8], message: &[u8], publicKey: &[u8]) -> bool {
        self.fault != Fault::rejectsEverySignature
            && publicKey.ends_with(&[0xAB, 0xCD])
            && signature.len() == 8
            && signature[4..] == message[..4]
    }

    fn remainingSignatureCount(&self, secretKey: &[u8]) -> Result<u64, OQSError> {
        let index = u32::from_be_bytes(secretKey.try_into().expect("4 bytes"));
        Ok(16 - u64::from(index))
    }

    fn totalSignatureCount(&self, _: &[u8]) -> Result<u64, OQSError> {
        if self.fault == Fault::countFails {
            return Err(OQSError::operationFailed);
        }
        Ok(16)
    }
}

fn xmssScheme(fault: Fault) -> IndexScheme {
    IndexScheme {
        description: &xmssDescription,
        fault,
    }
}

fn lmsScheme(fault: Fault) -> IndexScheme {
    IndexScheme {
        description: &lmsDescription,
        fault,
    }
}

/// A response file in the layout of liboqs, with the signature of index 3.
fn xmssResponseFile(message: &str, signature: &str) -> String {
    format!(
        "pk = ABCD\nsk = 00000003\n\n\ncount = 0\nseed = {responseSeed}\nmlen = 33\nmsg = {message}\nsmlen = 8\nsm = {signature}\nremain = 12\nmax = 16\n"
    )
}

#[test]
fn signedRunPrintsTheValuesTheSignatureAndTheCountsOfTheAdvancedKey() {
    let file = xmssResponseFile(responseMessage, "00000003B338DD75");
    let expected = format!(
        "pk = ABCD\nsk = 00000003\n\n\ncount = 0\nseed = {responseSeed}\nmlen = 33\nmsg = {responseMessage}\nsmlen = 8\nsm = 00000003B338DD75\nremain = 12\nmax = 16\n"
    );
    assert_eq!(
        StatefulKnownAnswerTest::text(&xmssScheme(Fault::none), &file),
        Ok(expected.clone())
    );
    let digest: String = SHA256::hash(expected.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        StatefulKnownAnswerTest::digest(&xmssScheme(Fault::none), &file),
        Ok(digest)
    );
}

#[test]
fn signedRunFailsAtEachCheckOfTheCProgram() {
    let run = |fault: Fault, file: &str| StatefulKnownAnswerTest::text(&xmssScheme(fault), file);
    let file = xmssResponseFile(responseMessage, "00000003B338DD75");
    assert_eq!(
        run(Fault::none, "sk = 00000003\n"),
        Err("XMSS-Test: unable to read 'pk' from the response file".to_string())
    );
    assert_eq!(
        run(Fault::none, "pk = ABCD\n"),
        Err("XMSS-Test: unable to read 'sk' from the response file".to_string())
    );
    assert_eq!(
        run(Fault::none, "pk = ABCD\nsk = 00000003\n"),
        Err("XMSS-Test: unable to read 'seed' from the response file".to_string())
    );
    assert_eq!(
        run(Fault::none, &file.replace("msg = ", "msx = ")),
        Err("XMSS-Test: unable to read 'msg' from the response file".to_string())
    );
    let otherMessage = format!("00{}", &responseMessage[2..]);
    assert_eq!(
        run(
            Fault::none,
            &xmssResponseFile(&otherMessage, "00000003B338DD75")
        ),
        Err(
            "XMSS-Test: the generator of the seed does not give the message of the file"
                .to_string()
        )
    );
    assert_eq!(
        run(Fault::signingFails, &file),
        Err("XMSS-Test: signature: the secret key has no signature left".to_string())
    );
    assert_eq!(
        run(Fault::shortSignature, &file),
        Err("XMSS-Test: the signature has 7 bytes, not 8".to_string())
    );
    assert_eq!(
        run(
            Fault::none,
            &xmssResponseFile(responseMessage, "00000004B338DD75")
        ),
        Err("XMSS-Test: the signature differs from the signature of the file".to_string())
    );
    assert_eq!(
        run(Fault::none, &file.replace("sm = ", "sx = ")),
        Err("XMSS-Test: unable to read 'sm' from the response file".to_string())
    );
    assert_eq!(
        run(Fault::rejectsEverySignature, &file),
        Err("XMSS-Test: the signature does not verify".to_string())
    );
    assert_eq!(
        run(Fault::countFails, &file),
        Err("XMSS-Test: total signatures: the operation failed".to_string())
    );
}

#[test]
fn verifiedRunOfLMSPrintsTheValuesOfTheFileInLowerCase() {
    // The signature of the file is one byte short and quoted, so it reads with a zero in
    // front, and the public key is one byte longer than the key that the scheme reads.
    let file = "#comment\n\nmsg = B338DD7511\n\nsm = \"000003B338DD75\"\n\npk = 00ABCD\n";
    let scheme = IndexScheme {
        description: &StatefulSignatureDescription {
            publicKeyLength: 3,
            ..lmsDescription
        },
        fault: Fault::none,
    };
    assert_eq!(
        StatefulKnownAnswerTest::text(&scheme, file),
        Ok("msg = b338dd7511\n\nsm = 00000003b338dd75\n\npk = 00abcd\n\n".to_string())
    );
}

#[test]
fn verifiedRunFailsWithoutAMessageOrAKeyAndOnAFailedVerification() {
    let run = |fault: Fault, file: &str| StatefulKnownAnswerTest::text(&lmsScheme(fault), file);
    let file = "msg = B338DD75\nsm = 00000003B338DD75\npk = ABCD\n";
    assert_eq!(
        run(Fault::none, "sm = 00\npk = ABCD\n"),
        Err("LMS_Test: the response file has no msg".to_string())
    );
    assert_eq!(
        run(Fault::none, "msg = B338DD75\nsm = 00\n"),
        Err("LMS_Test: the response file has no pk".to_string())
    );
    assert_eq!(
        run(Fault::none, "msg = B338DD75\nsm = 00\npk = 00ABCD\n"),
        Err("LMS_Test: unable to read 'pk' from the response file".to_string())
    );
    assert_eq!(
        run(Fault::none, "msg = B338DD75\npk = ABCD\n"),
        Err("LMS_Test: unable to read 'sm' from the response file".to_string())
    );
    assert_eq!(
        run(Fault::rejectsEverySignature, file),
        Err("LMS_Test: the signature of the response file does not verify".to_string())
    );
    assert_eq!(
        run(Fault::none, file),
        Ok("msg = b338dd75\n\nsm = 00000003b338dd75\n\npk = abcd\n\n".to_string())
    );
}
