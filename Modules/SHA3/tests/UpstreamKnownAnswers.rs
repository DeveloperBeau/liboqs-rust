//! Replicates the known-answer tests of liboqs `tests/test_sha3.c`.
//!
//! The vectors are the arrays of that file, copied as hexadecimal text. The four-way SHAKE
//! tests of the C file have no counterpart: the port computes four separate SHAKE functions,
//! so the single-function tests cover them.

use OQSNativeSHA3::{SHA3256, SHA3384, SHA3512, SHAKE128, SHAKE256};

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("hex"))
        .collect()
}

const sha3256Message24: &str = "616263";
const sha3256Message448: &str = "6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071";
const sha3256Message1600: &str = "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3";
const sha3256Expected0: &str = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
const sha3256Expected24: &str = "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532";
const sha3256Expected448: &str = "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376";
const sha3256Expected1600: &str =
    "79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787";

#[test]
fn sha3256OneShotMatchesTheUpstreamSHA3Vectors() {
    for (message, expected) in [
        ("", sha3256Expected0),
        (sha3256Message24, sha3256Expected24),
        (sha3256Message448, sha3256Expected448),
        (sha3256Message1600, sha3256Expected1600),
    ] {
        assert_eq!(
            SHA3256::hash(&bytes(message)).to_vec(),
            bytes(expected),
            "message {message}"
        );
    }
}

#[test]
fn sha3256IncrementalMatchesTheVectorsAndTheOneShotForm() {
    for (message, expected) in [
        ("", sha3256Expected0),
        (sha3256Message24, sha3256Expected24),
        (sha3256Message448, sha3256Expected448),
        (sha3256Message1600, sha3256Expected1600),
    ] {
        let input = bytes(message);
        let mut whole = SHA3256::new();
        whole.absorb(&input);
        assert_eq!(whole.finalize().to_vec(), bytes(expected));
        let mut pieces = SHA3256::default();
        for piece in input.chunks(7) {
            pieces.absorb(piece);
        }
        assert_eq!(pieces.finalize().to_vec(), bytes(expected));
    }
}

const sha3384Message24: &str = "616263";
const sha3384Message448: &str = "6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071";
const sha3384Message1600: &str = "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3";
const sha3384Expected0: &str = "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004";
const sha3384Expected24: &str = "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25";
const sha3384Expected448: &str = "991c665755eb3a4b6bbdfb75c78a492e8c56a22c5c4d7e429bfdbc32b9d4ad5aa04a1f076e62fea19eef51acd0657c22";
const sha3384Expected1600: &str = "1881de2ca7e41ef95dc4732b8f5f002b189cc1e42b74168ed1732649ce1dbcdd76197a31fd55ee989f2d7050dd473e8f";

#[test]
fn sha3384OneShotMatchesTheUpstreamSHA3Vectors() {
    for (message, expected) in [
        ("", sha3384Expected0),
        (sha3384Message24, sha3384Expected24),
        (sha3384Message448, sha3384Expected448),
        (sha3384Message1600, sha3384Expected1600),
    ] {
        assert_eq!(
            SHA3384::hash(&bytes(message)).to_vec(),
            bytes(expected),
            "message {message}"
        );
    }
}

#[test]
fn sha3384IncrementalMatchesTheVectorsAndTheOneShotForm() {
    for (message, expected) in [
        ("", sha3384Expected0),
        (sha3384Message24, sha3384Expected24),
        (sha3384Message448, sha3384Expected448),
        (sha3384Message1600, sha3384Expected1600),
    ] {
        let input = bytes(message);
        let mut whole = SHA3384::new();
        whole.absorb(&input);
        assert_eq!(whole.finalize().to_vec(), bytes(expected));
        let mut pieces = SHA3384::default();
        for piece in input.chunks(7) {
            pieces.absorb(piece);
        }
        assert_eq!(pieces.finalize().to_vec(), bytes(expected));
    }
}

const sha3512Message24: &str = "616263";
const sha3512Message448: &str = "6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071";
const sha3512Message1600: &str = "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3";
const sha3512Expected0: &str = "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26";
const sha3512Expected24: &str = "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0";
const sha3512Expected448: &str = "04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636dee691fbe0c985302ba1b0d8dc78c086346b533b49c030d99a27daf1139d6e75e";
const sha3512Expected1600: &str = "e76dfad22084a8b1467fcf2ffa58361bec7628edf5f3fdc0e4805dc48caeeca81b7c13c30adf52a3659584739a2df46be589c51ca1a4a8416df6545a1ce8ba00";

#[test]
fn sha3512OneShotMatchesTheUpstreamSHA3Vectors() {
    for (message, expected) in [
        ("", sha3512Expected0),
        (sha3512Message24, sha3512Expected24),
        (sha3512Message448, sha3512Expected448),
        (sha3512Message1600, sha3512Expected1600),
    ] {
        assert_eq!(
            SHA3512::hash(&bytes(message)).to_vec(),
            bytes(expected),
            "message {message}"
        );
    }
}

#[test]
fn sha3512IncrementalMatchesTheVectorsAndTheOneShotForm() {
    for (message, expected) in [
        ("", sha3512Expected0),
        (sha3512Message24, sha3512Expected24),
        (sha3512Message448, sha3512Expected448),
        (sha3512Message1600, sha3512Expected1600),
    ] {
        let input = bytes(message);
        let mut whole = SHA3512::new();
        whole.absorb(&input);
        assert_eq!(whole.finalize().to_vec(), bytes(expected));
        let mut pieces = SHA3512::default();
        for piece in input.chunks(7) {
            pieces.absorb(piece);
        }
        assert_eq!(pieces.finalize().to_vec(), bytes(expected));
    }
}

const shake128Message1600: &str = "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3";
const shake128Expected0: &str = "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef263cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e235b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea17cda7cfad765f5623474d368ccca8af0007cd9f5e4c849f167a580b14aabdefaee7eef47cb0fca9767be1fda69419dfb927e9df07348b196691abaeb580b32def58538b8d23f87732ea63b02b4fa0f4873360e2841928cd60dd4cee8cc0d4c922a96188d032675c8ac850933c7aff1533b94c834adbb69c6115bad4692d8619f90b0cdf8a7b9c264029ac185b70b83f2801f2f4b3f70c593ea3aeeb613a7f1b1de33fd75081f592305f2e4526edc09631b10958f464d889f31ba010250fda7f1368ec2967fc84ef2ae9aff268e0b1700affc6820b523a3d917135f2dff2ee06bfe72b3124721d4a26c04e53a75e30e73a7a9c4a95d91c55d495e9f51dd0b5e9d83c6d5e8ce803aa62b8d654db53d09b8dcff273cdfeb573fad8bcd45578bec2e770d01efde86e721a3f7c6cce275dabe6e2143f1af18da7efddc4c7b70b5e345db93cc936bea323491ccb38a388f546a9ff00dd4e1300b9b2153d2041d205b443e41b45a653f2a5c4492c1add544512dda2529833462b71a41a45be97290b6f";
const shake128Expected1600: &str = "131ab8d2b594946b9c81333f9bb6e0ce75c3b93104fa3469d3917457385da037cf232ef7164a6d1eb448c8908186ad852d3f85a5cf28da1ab6fe3438171978467f1c05d58c7ef38c284c41f6c2221a76f12ab1c04082660250802294fb87180213fdef5b0ecb7df50ca1f8555be14d32e10f6edcde892c09424b29f597afc270c904556bfcb47a7d40778d390923642b3cbd0579e60908d5a000c1d08b98ef933f806445bf87f8b009ba9e94f7266122ed7ac24e5e266c42a82fa1bbefb7b8db0066e16a85e0493f07df4809aec084a593748ac3dde5a6d7aae1e8b6e5352b2d71efbb47d4caeed5e6d633805d2d323e6fd81b4684b93a2677d45e7421c2c6aea259b855a698fd7d13477a1fe53e5a4a6197dbec5ce95f505b520bcd9570c4a8265a7e01f89c0c002c59bfec6cd4a5c109258953ee5ee70cd577ee217af21fa70178f0946c9bf6ca8751793479f6b537737e40b6ed28511d8a2d7e73eb75f8daac912ff906e0ab955b083bac45a8e5e9b744c8506f37e9b4e749a184b30f43eb188d855f1b70d71ff3e50c537ac1b0f8974f0fe1a6ad295ba42f6aec74d123a7abedde6e2c0711cab36be5acb1a5a11a4b1db08ba6982efccd716929a7741cfc63aa4435e0b69a9063e880795c3dc5ef3272e11c497a91acf699fefee206227a44c9fb359fd56ac0a9a75a743cff6862f17d7259ab075216c0699511643b6439";

#[test]
fn shake128OneShotMatchesTheUpstreamSHA3Vectors() {
    let mut output = [0u8; 512];
    SHAKE128::hash(&[], &mut output);
    assert_eq!(output.to_vec(), bytes(shake128Expected0));
    SHAKE128::hash(&bytes(shake128Message1600), &mut output);
    assert_eq!(output.to_vec(), bytes(shake128Expected1600));
}

#[test]
fn shake128SmallAbsorbAndSqueezeCallsGiveTheSameStream() {
    let message = bytes(shake128Message1600);
    let mut function = SHAKE128::new();
    for piece in message.chunks(8) {
        function.absorb(piece);
    }
    let mut reader = function.finalize();
    let mut output = vec![0u8; 512];
    for piece in output.chunks_mut(8) {
        reader.squeeze(piece);
    }
    assert_eq!(output, bytes(shake128Expected1600));
}

#[test]
fn shake128CloneAndFreshStateGiveTheSameStream() {
    let message = bytes(shake128Message1600);
    let reader = SHAKE128::absorbOnce(&message);
    let mut clone = reader.clone();
    let mut first = vec![0u8; 512];
    clone.squeeze(&mut first);
    assert_eq!(first, bytes(shake128Expected1600));
    let mut original = reader;
    let mut second = vec![0u8; 512];
    original.squeeze(&mut second);
    assert_eq!(second, first);
    let mut fresh = SHAKE128::default();
    fresh.absorb(&message);
    let mut third = vec![0u8; 512];
    fresh.finalize().squeeze(&mut third);
    assert_eq!(third, first);
}

const shake256Message1600: &str = "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3";
const shake256Expected0: &str = "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be141e96616fb13957692cc7edd0b45ae3dc07223c8e92937bef84bc0eab862853349ec75546f58fb7c2775c38462c5010d846c185c15111e595522a6bcd16cf86f3d122109e3b1fdd943b6aec468a2d621a7c06c6a957c62b54dafc3be87567d677231395f6147293b68ceab7a9e0c58d864e8efde4e1b9a46cbe854713672f5caaae314ed9083dab4b099f8e300f01b8650f1f4b1d8fcf3f3cb53fb8e9eb2ea203bdc970f50ae55428a91f7f53ac266b28419c3778a15fd248d339ede785fb7f5a1aaa96d313eacc890936c173cdcd0fab882c45755feb3aed96d477ff96390bf9a66d1368b208e21f7c10d04a3dbd4e360633e5db4b602601c14cea737db3dcf722632cc77851cbdde2aaf0a33a07b373445df490cc8fc1e4160ff118378f11f0477de055a81a9eda57a4a2cfb0c83929d310912f729ec6cfa36c6ac6a75837143045d791cc85eff5b21932f23861bcf23a52b5da67eaf7baae0f5fb1369db78f3ac45f8c4ac5671d85735cdddb09d2b1e34a1fc066ff4a162cb263d6541274ae2fcc865f618abe27c124cd8b074ccd516301b91875824d09958f341ef274bdab0bae316339894304e35877b0c28a9b1fd166c796b9cc258a064a8f57e27f2a";
const shake256Expected1600: &str = "cd8a920ed141aa0407a22d59288652e9d9f1a7ee0c1e7c1ca699424da84a904d2d700caae7396ece96604440577da4f3aa22aeb8857f961c4cd8e06f0ae6610b1048a7f64e1074cd629e85ad7566048efc4fb500b486a3309a8f26724c0ed628001a1099422468de726f1061d99eb9e93604d5aa7467d4b1bd6484582a384317d7f47d750b8f5499512bb85a226c4243556e696f6bd072c5aa2d9b69730244b56853d16970ad817e213e470618178001c9fb56c54fefa5fee67d2da524bb3b0b61ef0e9114a92cdbb6cccb98615cfe76e3510dd88d1cc28ff99287512f24bfafa1a76877b6f37198e3a641c68a7c42d45fa7acc10dae5f3cefb7b735f12d4e589f7a456e78c0f5e4c4471fffa5e4fa0514ae974d8c2648513b5db494cea847156d277ad0e141c24c7839064cd08851bc2e7ca109fd4e251c35bb0a04fb05b364ff8c4d8b59bc303e25328c09a882e952518e1a8ae0ff265d61c465896973d7490499dc639fb8502b39456791b1b6ec5bcc5d9ac36a6df622a070d43fed781f5f149f7b62675e7d1a4d6dec48c1c7164586eae06a51208c0b791244d307726505c3ad4b26b6822377257aa152037560a739714a3ca79bd605547c9b78dd1f596f2d4f1791bc689a0e9b799a37339c04275733740143ef5d2b58b96a363d4e08076a1a9d7846436e4dca5728b6f760eef0ca92bf0be5615e96959d767197a0beeb";

#[test]
fn shake256OneShotMatchesTheUpstreamSHA3Vectors() {
    let mut output = [0u8; 512];
    SHAKE256::hash(&[], &mut output);
    assert_eq!(output.to_vec(), bytes(shake256Expected0));
    SHAKE256::hash(&bytes(shake256Message1600), &mut output);
    assert_eq!(output.to_vec(), bytes(shake256Expected1600));
}

#[test]
fn shake256SmallAbsorbAndSqueezeCallsGiveTheSameStream() {
    let message = bytes(shake256Message1600);
    let mut function = SHAKE256::new();
    for piece in message.chunks(8) {
        function.absorb(piece);
    }
    let mut reader = function.finalize();
    let mut output = vec![0u8; 512];
    for piece in output.chunks_mut(8) {
        reader.squeeze(piece);
    }
    assert_eq!(output, bytes(shake256Expected1600));
}

#[test]
fn shake256CloneAndFreshStateGiveTheSameStream() {
    let message = bytes(shake256Message1600);
    let reader = SHAKE256::absorbOnce(&message);
    let mut clone = reader.clone();
    let mut first = vec![0u8; 512];
    clone.squeeze(&mut first);
    assert_eq!(first, bytes(shake256Expected1600));
    let mut original = reader;
    let mut second = vec![0u8; 512];
    original.squeeze(&mut second);
    assert_eq!(second, first);
    let mut fresh = SHAKE256::default();
    fresh.absorb(&message);
    let mut third = vec![0u8; 512];
    fresh.finalize().squeeze(&mut third);
    assert_eq!(third, first);
}
