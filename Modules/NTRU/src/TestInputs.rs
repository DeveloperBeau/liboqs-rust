//! The inputs and the digest of the unit tests that compare a function with its C function.
//!
//! The known answers come from a C program that called the internal functions of the NTRU
//! code of liboqs 0.16.0, such as `PQCLEAN_NTRUHPS2048509_CLEAN_poly_Rq_mul`, with the same
//! inputs. The program is not part of the repository.

use OQSNativeAlgorithmTests::{LinearCongruentialSequence, OutputDigest};
use alloc::string::String;
use alloc::vec::Vec;

/// The values of the seeded sequence of the C program: each value is the high 16 bits of the
/// next state.
pub(crate) fn sequence(count: usize, seed: u32) -> Vec<u16> {
    let mut sequence = LinearCongruentialSequence::new(seed);
    (0..count)
        .map(|_| (sequence.nextState() >> 16) as u16)
        .collect()
}

/// The low bytes of the values of a sequence, one byte for each value.
pub(crate) fn sequenceBytes(count: usize, seed: u32) -> Vec<u8> {
    sequence(count, seed)
        .iter()
        .map(|value| *value as u8)
        .collect()
}

/// The values of a sequence modulo 3.
pub(crate) fn ternarySequence(count: usize, seed: u32) -> Vec<u16> {
    sequence(count, seed)
        .iter()
        .map(|value| value % 3)
        .collect()
}

/// The digest of 16-bit values, each as two bytes, low byte first, as the C program prints
/// them.
pub(crate) fn valuesDigest(values: &[u16]) -> String {
    let bytes: Vec<u8> = values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect();
    OutputDigest::of(&bytes)
}

/// The output of the C program: the set, the function and the digest of the output of the
/// function, or a number. `exactBits` is the number of low bits in which `poly_Rq_mul` equals
/// the exact product for 20 seeded pairs of factors.
const cAnswers: &str = "\
NTRU-HPS-2048-509 product 4748e5675ef6f6ba459f3b8ec65a8ae4f8dd8373d398559b87da99879a7e3e85
NTRU-HPS-2048-509 exactBits 13
NTRU-HPS-2048-509 inverseModuloThree 3452b2fd4fb904f754ad2688953430920324320250f34f859f7fd3d89219bdca
NTRU-HPS-2048-509 inverseModuloTwo 185f84ee73c8abe03f0d9d03688d19aa99d0ad8031275ed8e17bf88e0a83c729
NTRU-HPS-2048-509 inverseModuloModulus 950a43262450a8087cabc6ed771ff877c289f8425ea33fa07316e204b8b4a9cd
NTRU-HPS-2048-509 ternaryBytes 1da0a974f6755d949f264bf67229f9750e9d951aa694ddedfc388d4bef31f942
NTRU-HPS-2048-509 ternaryPolynomial 2718fd5276b4362f76f7f168ed451b112ec62e389fa9695cbc72740da3241d67
NTRU-HPS-2048-509 modulusBytes 7b8bba70e81255a3cde9c79245569a312c9972f988941dc4388ca85698655691
NTRU-HPS-2048-509 sumZeroPolynomial 41d5e8959aaf820646472df9284af80f3d0c43484a8706822a7d822644bde70a
NTRU-HPS-2048-509 keyPolynomialF 0ddeb634b7d619ac79afbc00ca164800c56d3cb7f3a40483e8811cccbb0f1b8a
NTRU-HPS-2048-509 keyPolynomialG 6d7707d1c86b025143e864d220c09d4367fd091ec4976d2e27fb586d58aba6ae
NTRU-HPS-2048-509 blindingPolynomial 2c6546ad08fac53126ddddb62fcc3e17aad355c1cdd0420b0661239d606ec5d6
NTRU-HPS-2048-509 messagePolynomial a28519587e53bc4d69946229a6fb05f17b46cea8b8f81895d64e171948c9d22a
NTRU-HPS-2048-509 lift cd01a2f4541d65dc4879e6cebcb87ef5f204f036d8ad5e158e2eb5bd660564a5
NTRU-HPS-2048-509 ternaryFromModulus ef9af93986d3fd79270099a25af64722a9c6e11cc32c27f0a99ff0d5d281efe9
NTRU-HPS-2048-509 ternaryProduct a223cbfe02926344d58e6f87e339a675c6ba62f64ee89b301367ead669b8bdfb
NTRU-HPS-2048-509 productModuloPhi c609861dfab7a35e9c5380faec7abff6247116d5619a3390ac37f061d6127d34
NTRU-HPS-2048-509 publicKey 6290fe873c5080352c9a3e2e2dee3c30fd2043ee3622362be17504988b4b83d0
NTRU-HPS-2048-509 encryptionSecretKey 927eaed9a220a196403b978749126a35d387d74a0090f8055d44398ad959ba33
NTRU-HPS-2048-509 hostileDecryption 3f9bc2691528b0a5cff374e56af7443816c7c8317ad8c652168417c0f3593f94
NTRU-HPS-2048-509 hostileFailure 1
NTRU-HPS-2048-677 product a9edc9cc3a0c5e59663635d78534383fe553fe2a39051c203c4cf6ef8e172bc7
NTRU-HPS-2048-677 exactBits 13
NTRU-HPS-2048-677 inverseModuloThree d9a1ff09a6ea9dcbc1a81c9f3a5075d4c9c06ddb0f448eb7973c86ab29c0d89a
NTRU-HPS-2048-677 inverseModuloTwo 9d999c03e98a8a5381c8d82d3af50c3652eaae10ca8f9866fa041c2011bd35fe
NTRU-HPS-2048-677 inverseModuloModulus 30fa5885dc1f7f0578c8845a572ec4671cef1122ce537250da1c2e011541fda5
NTRU-HPS-2048-677 ternaryBytes 08742ae04b9d30726f1d32c01193189d2b73d4125fea39f9c534d4c2c12a176a
NTRU-HPS-2048-677 ternaryPolynomial b5e544b1ee89ce8899b8d9ffec177013c675e7400ac325a459cf120a68b31f35
NTRU-HPS-2048-677 modulusBytes 4ab388a01dbd0c1f83bf1221e113da669ea0f17107056b46b006260624b9da8b
NTRU-HPS-2048-677 sumZeroPolynomial 30f4846ece4bc6e1bb3f521ca078fbd5bdaf85f8efb45157167144c0cbab03eb
NTRU-HPS-2048-677 keyPolynomialF 91d71202f7066f9e8caf3b1094b477e6ed790e6b141777481511f4e5de403ca9
NTRU-HPS-2048-677 keyPolynomialG cd417237eb86c99d8351e94be6a07e75e5fce7a4cde333541b195c5021bf8c08
NTRU-HPS-2048-677 blindingPolynomial 4e6192580dc1199f21d8d35107dbe444405e165cf4cb1adf9eabed36ef21c71d
NTRU-HPS-2048-677 messagePolynomial c511abcfbbba3abf0b4a87222966b9716c251c363fe75faa749ce5eb25652224
NTRU-HPS-2048-677 lift 2d9ea21a5479081d24a4ec9381e743c53f6a16f534afe05ec7eb877bff58ffbf
NTRU-HPS-2048-677 ternaryFromModulus 864b2266396f43477d39a51691971b4dd36777eab25296193797466385c50a84
NTRU-HPS-2048-677 ternaryProduct 3aef9af231e28aa6af2e1e490d525a4e10178ff455d812a443b946e033656265
NTRU-HPS-2048-677 productModuloPhi da2dca957f757cd0b88c99c8e39d29a773b92f7002be9f0c7c55b97be3ad837a
NTRU-HPS-2048-677 publicKey ddc96284c5ceadea41da5216d06dfdeb872206973b2de922edf5bebdcc1f116e
NTRU-HPS-2048-677 encryptionSecretKey ee40b7ae4e4dbeccb6e217a6b6eea62016cce7212d583cb898ffd71606e30b5e
NTRU-HPS-2048-677 hostileDecryption 9abe8f95c8d19a2f41b1fb27c0a17c813d762b9adc08acd57cc5c986550c8e35
NTRU-HPS-2048-677 hostileFailure 1
NTRU-HPS-4096-821 product 327ae4a8dca3f4a58bea24ccbe3f55d883867cea7bb01a7dbda7f2deddc9caa7
NTRU-HPS-4096-821 exactBits 13
NTRU-HPS-4096-821 inverseModuloThree 43f25999bbf9a999bf2344161adb2c56870c33b45f310c3f584f99f6e35a5b06
NTRU-HPS-4096-821 inverseModuloTwo 5175ea37d00ae58698f2671efc69eee8c923ddedfdbebe9f884717f14aaddbbd
NTRU-HPS-4096-821 inverseModuloModulus f87e36d31741062fac8087b4e4623296c2a812db919c0220ddf605287362d543
NTRU-HPS-4096-821 ternaryBytes a802a7f1085091196c88c530310dc74c2d3869ea5dfef505b8086ccc53842ccb
NTRU-HPS-4096-821 ternaryPolynomial eddf8a7e0542123cdb8f464777021972b4e2f7190666192a9ac4c10dc3b3edb9
NTRU-HPS-4096-821 modulusBytes 65752d0787a4865ef64b0d3838a4473eeb4f9bf05a9c853cc9a3495635bb56c6
NTRU-HPS-4096-821 sumZeroPolynomial ffdbccacdd6402eaf3610070602aed9e526a36fab7d8d51019bb7c31eb86b451
NTRU-HPS-4096-821 keyPolynomialF e366ad319cbf28e4c24b2f5caee6e257f270d62bc19788096290e5f341c11893
NTRU-HPS-4096-821 keyPolynomialG 04c0fedc6fe06413fcdfdcc6f32cbfc58ca0e00a5f3b2d12af80460467ec1bca
NTRU-HPS-4096-821 blindingPolynomial faec220d0b66b8b7995eae9cbf90b8a518c987aee402591be22749f58f9e1e82
NTRU-HPS-4096-821 messagePolynomial 8191525c5bfc15a8d724ff1566e750ab727ca812fc3307657be4ea9471be9ded
NTRU-HPS-4096-821 lift 3923e8d351c398c57f2de1316dad1c8388358db4adab8bc617756e4ea78a572a
NTRU-HPS-4096-821 ternaryFromModulus 08b3157f9499fc95f3c49cca691d3aed1516bb194cf67c895396f99c04a707ba
NTRU-HPS-4096-821 ternaryProduct 56e8dbfc1cacf7cb186957bf963e59d69c0355779fa490afff2a6683996cac21
NTRU-HPS-4096-821 productModuloPhi 217c882a69796066c9787e06620cb69ca132b01733152050951bdee588be8446
NTRU-HPS-4096-821 publicKey e2971076a0eac3d9c78cb17f1cbc71ff4a73fab8badc1a56af19ff08d551bc08
NTRU-HPS-4096-821 encryptionSecretKey 0b6c703c0194b82c5595d6d3384481c3d01657110f408e1fa5d8c16e3ab2e408
NTRU-HPS-4096-821 hostileDecryption bc36b757106d3f94f01e10fc9e0182f2baf21058b6bf30713def9c7998fafc70
NTRU-HPS-4096-821 hostileFailure 1
NTRU-HPS-4096-1229 product 8051fa21408056199b74376acddeaf88b5704f40874ac391bfd1648be302d2fa
NTRU-HPS-4096-1229 exactBits 13
NTRU-HPS-4096-1229 inverseModuloThree dde1e90e447e9d9c90cbdf1ee5a6fb712fb33ade93a74979e7fe387ec78a2477
NTRU-HPS-4096-1229 inverseModuloTwo 77fe46b77033b38839116dbe1cd90afe87a5cee58511f61b7e31c43feff36e8e
NTRU-HPS-4096-1229 inverseModuloModulus d52c8c478477c3c22cc963cd33355106c88db4c9f188345c9e2d577dcdbddcc9
NTRU-HPS-4096-1229 ternaryBytes b31fad32b80aa738e032e77c093fe713532f826f764a8bf79c05571318640a32
NTRU-HPS-4096-1229 ternaryPolynomial 37e5cf3df47164dd6b697d6ac5cb952179a8cea7297b9005c7057514b4c77c78
NTRU-HPS-4096-1229 modulusBytes 25ac1a0ca638fb38b07ff7f2582f5e9b08631e128190a16ad020377a34f25a01
NTRU-HPS-4096-1229 sumZeroPolynomial 683931fd53d40e927cba9135d30b0dcf37258abddceadbe3b0440fe359a226b1
NTRU-HPS-4096-1229 keyPolynomialF 9c4eb8e4f0c3e74a736fc67c05a3a32b0bd71274e23491c049197755f334e9cc
NTRU-HPS-4096-1229 keyPolynomialG 5044be443a83cc6da177e38d277a439586f187235d32677a5585c1e3a5406f42
NTRU-HPS-4096-1229 blindingPolynomial 747d5afe3d1f46bb57cc890d30b9440fb2024b57f7b8ad934b2abb7e39af0795
NTRU-HPS-4096-1229 messagePolynomial 5e78edaa3af315a37fcffce59d26af463e29c82f87495c35ad2def671a79e128
NTRU-HPS-4096-1229 lift c0d858ab1bc9cdadb1d142dd0d722ede02e28f0d3adcab29ca650771ff4eac47
NTRU-HPS-4096-1229 ternaryFromModulus a0d028f88ab4b6c2a914ecdb4285b74b3eb35b89247281c3716940ab9768f0ee
NTRU-HPS-4096-1229 ternaryProduct dfaa2f8eb80d046ed19e94270af5feaf8dc4a66603f3514a8424fd111c6c9466
NTRU-HPS-4096-1229 productModuloPhi 6ea2548ed00fbf2728d6cf01eb97444f5e9789614b3fb6431a4d8255746e52b4
NTRU-HPS-4096-1229 publicKey 7dda35dc47a0a3a71ded0fbcb186d3c3dd5dbbfe2f40d6001419e4fb1b431c0c
NTRU-HPS-4096-1229 encryptionSecretKey 97dc2f7f8ed2f5d16048841e12e7d56da67ddbdf0d4af276bae5ccf9ae47cf74
NTRU-HPS-4096-1229 hostileDecryption d7cedabdd7b63b374ee86df65fea3a731108b83cf598e7dee388378104ba9348
NTRU-HPS-4096-1229 hostileFailure 1
NTRU-HRSS-701 product ad748483c312d83f6d5033bf15eee99a02293db960f2e313103a39da3d955dc6
NTRU-HRSS-701 exactBits 13
NTRU-HRSS-701 inverseModuloThree c559bc9a887d3ab934b21b05e5c946ca5e2568f3135b8dcddd4fefa0fe3afe5d
NTRU-HRSS-701 inverseModuloTwo 643ca4c934266111d8937f3a1a4cc1c355126db8cee5efbdddeb79cf17fadcca
NTRU-HRSS-701 inverseModuloModulus 1b177feee0406585b80f9866c528e8c20d07df56fdcada07fdf94410019c98e0
NTRU-HRSS-701 ternaryBytes 20ac6db6e223f4ec7e81ab75b608b91208fad6ffefa8ac2e0ea9c35249b00f2c
NTRU-HRSS-701 ternaryPolynomial 61152223eba505cda75115c2c25a1f2485dca77e9a47292a7b640610cf20d7e4
NTRU-HRSS-701 modulusBytes fba7803cc4fe86bd1079e617411e7084fb3dbc395bc7e4513f81e15b5c368cbf
NTRU-HRSS-701 sumZeroPolynomial 418987875ff1068cf0394ba63228f221470f17d46a16ae9ec0d4629d5b2e64b8
NTRU-HRSS-701 keyPolynomialF f55251c1d3dbce2b30ba56a8c4b4f5ab14e2d943d1a6dcc66ed5f78d3938cd40
NTRU-HRSS-701 keyPolynomialG c1d6f68e286eb68b5e1de8fd0464b73847bd7fe01c2a34edc0adc09e357bbe1e
NTRU-HRSS-701 blindingPolynomial a6c1e1b684086f3c07d90e1e1a2da556cac9e866d3dd111867c4075c72c8d1b1
NTRU-HRSS-701 messagePolynomial 9ff51f831943fb991330ae8ac67e0f826c9433b42f58b4d4f4ded27b69934514
NTRU-HRSS-701 lift b1d605f0b9d0d2e4c3cc784a860cf25bbd23de1365869178f5ff9eb6c951308c
NTRU-HRSS-701 ternaryFromModulus ead5db6efa0eafd6680cbe09ce377af48be8e9070376a7037ea610b9fb1effa0
NTRU-HRSS-701 ternaryProduct 3276b4f3fc7c9f2e128247e22d000421388e82142c5dff4f360f11249918dd49
NTRU-HRSS-701 productModuloPhi 91a67ca22464612765b7516b6e9ccc9a4982624ca3c3c20f0d6ce8a1ec405541
NTRU-HRSS-701 publicKey 5a4608a23904506dfbfe8bc869cb718d46925b488a2eff76ec447a5f31c25bbc
NTRU-HRSS-701 encryptionSecretKey 6b0cb197d2da3d5a1cf6b033dbc8ecd92c091dc65577adba767c2c378a57d67a
NTRU-HRSS-701 hostileDecryption fade130b985b704553b2708e15d13b3bed71b3f701d5f87f7d6320f961169251
NTRU-HRSS-701 hostileFailure 1
NTRU-HRSS-1373 product b501362a1db6429e60a96851da15d65523c7f725420c90cebcf8833423053a82
NTRU-HRSS-1373 exactBits 16
NTRU-HRSS-1373 inverseModuloThree fb503774dea20a4d3769399c332691c57e4ac8e3a4f89d8e27381886f8d75384
NTRU-HRSS-1373 inverseModuloTwo af654437ce42708a2326c724acbd7c8edb08668cef65a1e987e683203e7eb605
NTRU-HRSS-1373 inverseModuloModulus b6dc8c17e3058cf2b84efa85feeab36f2e97b80e70c75f5022fae749088ecd03
NTRU-HRSS-1373 ternaryBytes 98de8343deaa983668cb3d1f4332877864f8e6ade8c662ebe3d0c503de6e3bbb
NTRU-HRSS-1373 ternaryPolynomial c94476d216139f2284cf841d6ed3704f95d68c26b05e80b2b6d82722f275c725
NTRU-HRSS-1373 modulusBytes df9d3c59be62d304af23ad742e47781154a08a5d419a663d99537b5aadc5e8c7
NTRU-HRSS-1373 sumZeroPolynomial aa3af6a086282bbcd4662e8110d12b5f6e5b1e518c0c890b461a73fc643c9d93
NTRU-HRSS-1373 keyPolynomialF 16c1b870ac8d5cc1a6640b9397816c169dc75b965114a0392e0c991a76b1decf
NTRU-HRSS-1373 keyPolynomialG e568b6230e78bacf16f226dad2eb8e710740a2478403ca94e11505d3a5e000b7
NTRU-HRSS-1373 blindingPolynomial 5f128a6a53cae12aabca95c96fd4529497504f48e3b03ca4679c7f6ad4c3f5e2
NTRU-HRSS-1373 messagePolynomial 7a02906cbbe2be07c0d71763eb89a58b2f11ea03fb013e459270dad45be239bf
NTRU-HRSS-1373 lift bf5e1aa9e16d7c59fca9758ec597a66ca168ca004d073e9ca9b0d2dab2503010
NTRU-HRSS-1373 ternaryFromModulus e15f03ad78d44129f9c25047e0c4e29950208ea15586b030218343a1e47474b2
NTRU-HRSS-1373 ternaryProduct 1cc2217a1b007b2eb8312faa81cbdb44115b5dff70f26dfe48621aab2dd7a14d
NTRU-HRSS-1373 productModuloPhi 8603b6f46cb6c47af96b5a36b5b152333da3dd2e2ec3e253d22fa2e30ebed9d4
NTRU-HRSS-1373 publicKey 86428e5a94dd9af87871fc5a85d0c30068c6d6a8a3ba436ef4f15d92d294f322
NTRU-HRSS-1373 encryptionSecretKey d551654540b1a40909a52477963475ccf8ad3cb9c0811b4a5b845bd48c38e4e7
NTRU-HRSS-1373 hostileDecryption 564f109be8468898cbe83064125ab4909dbf6738441c3b8bb6d1c2038b49c38c
NTRU-HRSS-1373 hostileFailure 1
";

/// The answer of the C program for a set and a function.
pub(crate) fn cAnswer(set: &str, function: &str) -> &'static str {
    cAnswers
        .lines()
        .find_map(|line| {
            let mut parts = line.split(' ');
            let isMatch = parts.next() == Some(set) && parts.next() == Some(function);
            if isMatch { parts.next() } else { None }
        })
        .unwrap_or_else(|| panic!("the C program gives no answer for {set}, {function}"))
}

/// Every parameter set, in liboqs order.
pub(crate) fn everySet() -> [&'static crate::Parameters; 6] {
    use crate::parameters::{
        ntruHPS2048509, ntruHPS2048677, ntruHPS4096821, ntruHPS40961229, ntruHRSS701, ntruHRSS1373,
    };
    [
        &ntruHPS2048509,
        &ntruHPS2048677,
        &ntruHPS4096821,
        &ntruHPS40961229,
        &ntruHRSS701,
        &ntruHRSS1373,
    ]
}
