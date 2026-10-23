//! The inputs and the digest of the unit tests that compare a function with its C function.
//!
//! The known answers come from a C program that called the internal functions of the NTRU
//! code of liboqs 0.16.0, such as `PQCLEAN_NTRUHPS2048509_CLEAN_poly_Rq_mul`, with the same
//! inputs. The program is not part of the repository.

use OQSNativeSHA3::SHA3256;
use alloc::string::String;
use alloc::vec::Vec;

/// The values of a simple seeded sequence, the inputs of the C program: the state takes
/// `state * 1103515245 + 12345` modulo `2^32`, and each value is the high 16 bits of the state.
pub(crate) fn sequence(count: usize, seed: u32) -> Vec<u16> {
    let mut state = seed;
    (0..count)
        .map(|_| {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            (state >> 16) as u16
        })
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

/// The digest of the C program: the SHA3-256 of the bytes, in lower-case hexadecimal.
pub(crate) fn digest(bytes: &[u8]) -> String {
    SHA3256::hash(bytes)
        .iter()
        .map(|byte| alloc::format!("{byte:02x}"))
        .collect()
}

/// The digest of 16-bit values, each as two bytes, low byte first, as the C program prints
/// them.
pub(crate) fn valuesDigest(values: &[u16]) -> String {
    let bytes: Vec<u8> = values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect();
    digest(&bytes)
}

/// The output of the C program: the set, the function and the SHA3-256 of the output of the
/// function, or a number. `exactBits` is the number of low bits in which `poly_Rq_mul` equals
/// the exact product for 20 seeded pairs of factors.
const cAnswers: &str = "\
NTRU-HPS-2048-509 product a7c5d866275fc30f0a7bf98e2bbf6ac4538d265b5ad86b7c99cfe291db5930a2
NTRU-HPS-2048-509 exactBits 13
NTRU-HPS-2048-509 inverseModuloThree 1940d1d1a7fcecdb22c0c0c8c39aa9df736375440faaac8c44bab3bae6e1be05
NTRU-HPS-2048-509 inverseModuloTwo 7c92016fd899e635973611ed52cc7d1745d7f962e07eac898d889acaeaf71004
NTRU-HPS-2048-509 inverseModuloModulus 7b7076c3c6ebd748b94fbe9a7f5de0a7a7bd8a834c652c0fe94a7b8ec7600b2d
NTRU-HPS-2048-509 ternaryBytes 4e99da64c59723afab775a1804d6879a7bdc9b6b98b8890c1175f8d7827de106
NTRU-HPS-2048-509 ternaryPolynomial 6e4317959fc7d8c890660b212adfe2f03f53e602e5d50132419bf09bc41649db
NTRU-HPS-2048-509 modulusBytes 98aa17e3dac770bf9a019f8da088f9f62ca1c073adaf47c74fba5c3eda65b9af
NTRU-HPS-2048-509 sumZeroPolynomial 75541ed984990df4fd3e9c91f3deece913a380a458b63a03c85a4216be903a60
NTRU-HPS-2048-509 keyPolynomialF a5474e53363c21dcfe9692b90c706630ca9244a625b9de4c3ea66005cfed5547
NTRU-HPS-2048-509 keyPolynomialG e462677fe841c9e776decc8d015603827ccd9d1c78754a84ef7fdb475b5fd72d
NTRU-HPS-2048-509 blindingPolynomial 481c24019f2dee76773a30c421c1c94cdf69b3d796f2b09a9695529835c06e3a
NTRU-HPS-2048-509 messagePolynomial e467fe3510c4d1301b59b1f95831691a68744b5c976140920170f0fc87f0ce7e
NTRU-HPS-2048-509 lift ae1c32632146083b5ab4ad038551bdb65a94e5abb2b75122046c59138a139f34
NTRU-HPS-2048-509 ternaryFromModulus 8504acc177078f161be3ba7de6652b4f654a6ce0020ec156200e2e93d9eb6c04
NTRU-HPS-2048-509 ternaryProduct 23f98c856973b9638a743a6be2aa6555e8ee7f83fcbb5889bf4d4ca4a48714ce
NTRU-HPS-2048-509 productModuloPhi 82d683b1532583ff0d44490b6d399b27c26a9ed3ef6e2eafac1b2d495c9ead58
NTRU-HPS-2048-509 publicKey 9b48e272513907fae47abd3cac3ff270261e596a8b578e6a4e721827f2b2722e
NTRU-HPS-2048-509 encryptionSecretKey cecc74ec9c2cc7314666addf95f9b7e1591e793b502f7a8bb6cbbe67c75b8260
NTRU-HPS-2048-509 hostileDecryption 180a9a1e1c4d6d2131c1846069d5ace783874f69efd4d9bd73fcdd2b9370959a
NTRU-HPS-2048-509 hostileFailure 1
NTRU-HPS-2048-677 product 2b016dcb34a9a24fdba306fc405be6782fd7e6348edbc72ea652b2b5802f9eeb
NTRU-HPS-2048-677 exactBits 13
NTRU-HPS-2048-677 inverseModuloThree 9f7502fa1130d587db97d8f1061f76d92399f76180256b37d1110787551a516d
NTRU-HPS-2048-677 inverseModuloTwo 266994029705dc5a03064d9453f63f6e66b451cbb1ca15d6b61165bb3fabfd56
NTRU-HPS-2048-677 inverseModuloModulus a9c2a3e5379802c2de1e045a4683f525abd6ed654f914927817e636a2be547aa
NTRU-HPS-2048-677 ternaryBytes 2df7a29537bfcca299c901aed0bf6fdd0c75d43a1d0aff217fea694b19797667
NTRU-HPS-2048-677 ternaryPolynomial 22e3e77682d98f148cd534f23a072cc278b7be42ec267972f916fbf6dc1bc0fb
NTRU-HPS-2048-677 modulusBytes f23647a1b7eafd4f83a7e1e67e8ff624d23ac03cb715efb0db71b842029a2e0c
NTRU-HPS-2048-677 sumZeroPolynomial ffa5eb853c7feb592d3a2b8f7c55426582a00a995b5d760daca58ff6515f0b07
NTRU-HPS-2048-677 keyPolynomialF 4d185d40689e1c1f4dfcc0d052b62eb93702475d69a624c9d98afd06f721a5f6
NTRU-HPS-2048-677 keyPolynomialG b19046668abb39f34b3e8cf3a3113479a6181e13122cbb54b0fabec6a676e411
NTRU-HPS-2048-677 blindingPolynomial 74fef6c0cabd24c5ed5496072b87062e058999a5789ad3bed73c1a41de514503
NTRU-HPS-2048-677 messagePolynomial 2ab038b2836da31a1419330b2b899d633176d7dfeb34d3cdbcbcd285c5d5bb23
NTRU-HPS-2048-677 lift c50d1f22148a2e1e72886d697ddefb821569bb84ebc1a8feb995c53deb7cf8f3
NTRU-HPS-2048-677 ternaryFromModulus 369527ba46942ce40fdf4cdce514369d625e1535df1f2cbc386ed68faf2c6dfe
NTRU-HPS-2048-677 ternaryProduct 217f3e7886a5d38712704870147de2395e027c130b2c545831de3d80f4bec8cc
NTRU-HPS-2048-677 productModuloPhi 4115192d734d94af37ce45a229295c1290248c26fd024d43503260ca85e260c2
NTRU-HPS-2048-677 publicKey 8b8e09d223ec7313ed439a04ec95840f5bc440c7798bc89e4be5f3fea35858e8
NTRU-HPS-2048-677 encryptionSecretKey 6d8833aa9ae138b882c69e23034f49dcc5c6b4743a8af3a5374cdc325fe15211
NTRU-HPS-2048-677 hostileDecryption 558d0c605489e66d8e8cbebbd96b86fd8315edd18d8ca4e7ac0a913743cc4788
NTRU-HPS-2048-677 hostileFailure 1
NTRU-HPS-4096-821 product cba8b8cc6afb8808e5b25e65bba1106d3e3c7101cade4257099e8acc1556b33b
NTRU-HPS-4096-821 exactBits 13
NTRU-HPS-4096-821 inverseModuloThree c169d269419dca733f033aebc2ce8fe388dd85649b70a012523cd8bd9fae3765
NTRU-HPS-4096-821 inverseModuloTwo 7954ae21bd09c3fc091af9741e38775851e4f2a844e9bd9054055b6a87ab9fa0
NTRU-HPS-4096-821 inverseModuloModulus 262f256565fe0cafbd696b22a99aadd07f02a0d4581bd439a33f8a37870db990
NTRU-HPS-4096-821 ternaryBytes 1716ae89622cdbb078978f26192a3676f3ac873d5067e80667537111a8aaff90
NTRU-HPS-4096-821 ternaryPolynomial 18500255c096961cc9dad230b889b40cfd17671d5f8dd9fb4610a442a984fdb4
NTRU-HPS-4096-821 modulusBytes 10203b2752f4de89d9e159555b4a063db8b803e49d07a3142e58a0124d68911b
NTRU-HPS-4096-821 sumZeroPolynomial 0b45ecebe5c1df4e0f8b3fd50d7ec119740917c97c80f21085c5a57b6f061e1a
NTRU-HPS-4096-821 keyPolynomialF db69d12ac9003893fc6faffe0a4f1db5fac2855f78e5cb2b4b85bc844b2baa0c
NTRU-HPS-4096-821 keyPolynomialG fe226e37ed4b4877784ff8620aaa0a408bdd3bad4fcf36f8bc7a0c7bf3fbfda9
NTRU-HPS-4096-821 blindingPolynomial 4bb7583421513750335aa476032bf2c5307393e6a128ba4d325f9eadabd9b309
NTRU-HPS-4096-821 messagePolynomial 68e84bfb8900e197ed931f35063c3164f3c0d06fd9fc107f8872da837d6f79ad
NTRU-HPS-4096-821 lift 519e6feb5953cc85c8b20b2aff5e0d5866fc83e91fd4056f0a67eb78332d738b
NTRU-HPS-4096-821 ternaryFromModulus 8d9be18b8f15f3c765f84e92a608df25404cd2aa8cd843af4110739a004248a8
NTRU-HPS-4096-821 ternaryProduct 9c8e2c4a88f06a0f858928f8e639a64320b3e914b8de969f68c913cc1ee58243
NTRU-HPS-4096-821 productModuloPhi 32d8bd38a13d706fbde781e44128fc35b5f3d6c6621ad80ccbb769c16d563de4
NTRU-HPS-4096-821 publicKey 4cf61198997966ca679ce8266b8938020fc02e5586ab4bc46fb0799d8b17a078
NTRU-HPS-4096-821 encryptionSecretKey e9c31d4cb5831e572609736d23bcb5c917eb53ddaf14f7a29a3eb8a2e7ae6acd
NTRU-HPS-4096-821 hostileDecryption 5d44531405787a9a8aaf602da2ced797116d580d74c4d636b184cb6fc3facd5e
NTRU-HPS-4096-821 hostileFailure 1
NTRU-HPS-4096-1229 product 51e02beda569fb32b33ba71ee129f602e08603c72ebc62f7455e3dcf2921ac85
NTRU-HPS-4096-1229 exactBits 13
NTRU-HPS-4096-1229 inverseModuloThree de8ec8cfd3562577a756708eecd08d84ce33e40c5d1cfaf36a75e0e95d25267c
NTRU-HPS-4096-1229 inverseModuloTwo 1fcd7fb17628a567bebb0fee9a7bbc683a328e438a78232dc3eeeda692bb50e9
NTRU-HPS-4096-1229 inverseModuloModulus b833ba27090c86a981f13fb46a74fc974650f575e19dc6ede1608652da31a162
NTRU-HPS-4096-1229 ternaryBytes 88f7df0eed017336993fefbae30ad066f668cc2450d590823f27fff626ae48f1
NTRU-HPS-4096-1229 ternaryPolynomial 31a13ef06f0bd8e4064b55ecc052c030f4e43836b5b816f5d99a22d6497f07b4
NTRU-HPS-4096-1229 modulusBytes 489404ff73b722b28da14a85925e00d434d86c8977efaba1a9940aa2821a2e9f
NTRU-HPS-4096-1229 sumZeroPolynomial 602118da018230add3022b6b870ce45ba2bf1a9e2d638dca0de7f46c5aeb0913
NTRU-HPS-4096-1229 keyPolynomialF 0fdf5137b3216161ec335204a72c3086f9d1b4626d54532dfb7a3e0bb2541201
NTRU-HPS-4096-1229 keyPolynomialG 865b9c78527fcce07acc7a40e764a563de6a339d92ee07c1ec444ed9294449ab
NTRU-HPS-4096-1229 blindingPolynomial e3bb7778a9df8986969619d238cea5d3fe9d53e174a9147211fcd96a581f4ebe
NTRU-HPS-4096-1229 messagePolynomial fe51550641bcd374b27c0141575e68499be5acc447182592ad10b14662fa0259
NTRU-HPS-4096-1229 lift 0dfd7865662f8cca39e81cfe6644dd58f6f350f4534f18f1c81066799dbf1f2a
NTRU-HPS-4096-1229 ternaryFromModulus d4228ddfba05f2f031589cdaa97448b13c35a67f5e905ff4d94ee8b09f372220
NTRU-HPS-4096-1229 ternaryProduct 936761878e249b6ca17f7d3e596a18bd56c1321be6991e53ab226bee381f26f7
NTRU-HPS-4096-1229 productModuloPhi 82878c55a54076f1dae15571a9a14cf613f78cafa9e5ac67cd03b6ff940d8898
NTRU-HPS-4096-1229 publicKey dd9f971441272c9368fed3af0eec710c6f9b1429ca1660331dec0cb340070fc8
NTRU-HPS-4096-1229 encryptionSecretKey e8cc9d1fd30ac51bd3b20a3e3f5424752ae92bd981aef913e4dc13988be2657f
NTRU-HPS-4096-1229 hostileDecryption df8184d92d1dd2bf45af0c147a54066e4cda94035b6206bd162e41702a7a2078
NTRU-HPS-4096-1229 hostileFailure 1
NTRU-HRSS-701 product 1cfbc4959670f17ca211e33340bcb08780723d66d300bf72dcbc7275a1790f6a
NTRU-HRSS-701 exactBits 13
NTRU-HRSS-701 inverseModuloThree 5e40dc5494fba4b3d9a543c88774fb8414611d404a04b91d0d185a4702784815
NTRU-HRSS-701 inverseModuloTwo 9d6bbb77e812ce6f673006e574e9ac81186ae7005d83833d4842bb4256f8a8ea
NTRU-HRSS-701 inverseModuloModulus 696eba9bf15be83ff413113d1e349c0d663c338e3e069245fa6b85571cd0d2a8
NTRU-HRSS-701 ternaryBytes fc00a5f35e148b6e70fa864f791aebcb8535f95776a3dd079965511c84f168e4
NTRU-HRSS-701 ternaryPolynomial a78bc4853a2da09997b5fc7f2b038925b652a4272d8b77137883d676ecc243aa
NTRU-HRSS-701 modulusBytes 1936f2d0360a90a35bd1079ae4cf77939d0253cb7440d128516da4436eff7f1b
NTRU-HRSS-701 sumZeroPolynomial 8acdcf566a4126e87a2fd45f5759e0c4a792d1fff2a17bec0261ea735542b6ed
NTRU-HRSS-701 keyPolynomialF 0b8d942f33cdbf3e392c599f18c35853dd35f9c12e7c86631c663b99887efdea
NTRU-HRSS-701 keyPolynomialG 1d8b2a15be61576d712fdc966592e91c906462780192bfa9cdf71cea0b3cc4f6
NTRU-HRSS-701 blindingPolynomial 54120e6cba5aef985b02e97caacba3c36a359a0fdf0147245d4d614969e6b732
NTRU-HRSS-701 messagePolynomial 65a175eb0689daff45a7bb01acae6d26ec78e52f7849a46143f7f64ba1f92437
NTRU-HRSS-701 lift f0a9da1eb89601c8a8863073e32bfe60cd1634db805dc70253fbf2a9e37954f8
NTRU-HRSS-701 ternaryFromModulus 56764dd34a0603595601d27992bd57d609f3ed25875def50aeab6f4310e3e382
NTRU-HRSS-701 ternaryProduct f37d0c72654f13fceef8abc7c47e5cd5ae4cd99c2f99825ff7552610af472cd2
NTRU-HRSS-701 productModuloPhi e91cd96c41c14884008b79674f853865c68f66b764cebda921e536434dde9273
NTRU-HRSS-701 publicKey 0adf141b5b25c9dae740891e4b5b835475d241f133b2f53cd23e27d274b688ca
NTRU-HRSS-701 encryptionSecretKey 3c8d2f9954133e2b208cc500588fc6befe09113b1f8afe7fe60a92aefe86232a
NTRU-HRSS-701 hostileDecryption c4cd68334dd4f2983fde947e181193b8f801fbd9f0c32197ac68b45345cc7331
NTRU-HRSS-701 hostileFailure 1
NTRU-HRSS-1373 product f5eb43e3612d67644b9fa5f85ae6e0e3fd6931230ad3e8e897940ba29ff42041
NTRU-HRSS-1373 exactBits 16
NTRU-HRSS-1373 inverseModuloThree 8e8f80391a8a7b1e8ce025281c0cd208f401d2c334964a86e36f4d3df0abde7e
NTRU-HRSS-1373 inverseModuloTwo 6759ff8de186f0d1a121625fe57f04964a3062cdc2645938470b663f0b56ec8e
NTRU-HRSS-1373 inverseModuloModulus 548413a1988b9fdce6e46d7f9e0815a28debdfee3fbc3322ee3faac2ebd02ab7
NTRU-HRSS-1373 ternaryBytes 89340a80d05f59d44ec3a64789928bd8acb337148cdd8239fc51ddefb6ecefbb
NTRU-HRSS-1373 ternaryPolynomial ebfa1f6f917e251c20315a1bbe51177bd43d860b56883003a0fc60143a50a8c0
NTRU-HRSS-1373 modulusBytes 27e75a57ff7bde009baf290e8a6a36ff82ce866b79642d8ab66de883d43a36c8
NTRU-HRSS-1373 sumZeroPolynomial 793db6dffc6adc6b6c610c3a9ae37c622d471025ae249895fe9673c60f345030
NTRU-HRSS-1373 keyPolynomialF da0b898f22cbf6ee6e5444804dd6e51faa2a3bf2638e4d24592a59914853c96f
NTRU-HRSS-1373 keyPolynomialG 1ec1920243d9835665f17e9a3ebafe677bed0c245fd2d10fe0f9c4e5d6d4ed9d
NTRU-HRSS-1373 blindingPolynomial e1d8bdadab94ebb6d0f882042dea10acc4c65419da05d7b28c2ba109250f6889
NTRU-HRSS-1373 messagePolynomial 1a0662425d18dd8f3598589c5227e6f39dedb6763787d91dc66e81f530615caf
NTRU-HRSS-1373 lift 37a6c7fdc9df08ab117c49de2a3e02351c784985b72cb7ad3d875df6e3551196
NTRU-HRSS-1373 ternaryFromModulus df2e54d4e844313c9ba0b811b675a5da1958f3085a89de8d6d0c0d2e993b89e6
NTRU-HRSS-1373 ternaryProduct d91c45fb3e2445467d3359be4b182fb1dfdab9ea9546e9c988d5130bfe3857d7
NTRU-HRSS-1373 productModuloPhi bdfbdf0519677fa248a43eebfc05f5bccd6ff85035f6e8862d5c96e4ccdba77d
NTRU-HRSS-1373 publicKey 269313a2a2f3a1187fb651229972e448ae7e818414caf5d370a589f389e0c692
NTRU-HRSS-1373 encryptionSecretKey 80eaac329fa552886475b3dabb4a9c38fb6fdfea23cdcbeb308a0d232a2b3496
NTRU-HRSS-1373 hostileDecryption 7cf9fbd16286b18ca6795b5f9999244a16405ca41f49f7eac1b84b629361d9c6
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
