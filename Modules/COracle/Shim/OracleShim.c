// SPDX-License-Identifier: MIT
//
// The C side of the parity tests. Each function wraps one liboqs call in a plain signature, so
// that the Rust side never depends on the layout of a liboqs struct. Each function returns the
// OQS_STATUS of liboqs, or OQS_ERROR when liboqs does not know the algorithm.

#include <stdlib.h>
#include <string.h>

#include <oqs/aes.h>
#include <oqs/oqs.h>
#include <oqs/rand_nist.h>
#include <oqs/sha2.h>
#include <oqs/sha3.h>

#include "test_helpers.h"

// The hash-sigs code of LMS inside liboqs. The build script adds its folder with -iquote, so
// that its endian.h never hides the endian.h of the system.
#include "endian.h"
#include "hss.h"
#include "hss_internal.h"
#include "hss_sign_inc.h"

// The facts of a KEM, as OQS_KEM holds them.
typedef struct {
	const char *name;
	const char *algorithmVersion;
	uint8_t claimedNISTLevel;
	uint8_t isINDCCASecure;
	size_t publicKeyLength;
	size_t secretKeyLength;
	size_t ciphertextLength;
	size_t sharedSecretLength;
	size_t keyPairSeedLength;
	size_t encapsulationSeedLength;
} OracleKEMFacts;

// The facts of a signature scheme, as OQS_SIG holds them.
typedef struct {
	const char *name;
	const char *algorithmVersion;
	uint8_t claimedNISTLevel;
	uint8_t isEUFCMASecure;
	uint8_t isSUFCMASecure;
	uint8_t supportsContext;
	size_t publicKeyLength;
	size_t secretKeyLength;
	size_t signatureLength;
} OracleSignatureFacts;

// The facts of a stateful signature scheme, as OQS_SIG_STFL holds them.
typedef struct {
	uint32_t objectIdentifier;
	const char *name;
	const char *algorithmVersion;
	uint8_t isEUFCMASecure;
	uint8_t isSUFCMASecure;
	size_t publicKeyLength;
	size_t secretKeyLength;
	size_t signatureLength;
} OracleStatefulFacts;

// Randomness. liboqs has one global random source, so the Rust side holds a lock around each
// use of this file.

static OQS_KAT_PRNG *katGenerator = NULL;
static void (*callbackFill)(void *, uint8_t *, size_t) = NULL;
static void *callbackContext = NULL;

static void releaseKATGenerator(void) {
	if (katGenerator != NULL) {
		OQS_KAT_PRNG_free(katGenerator);
		katGenerator = NULL;
	}
}

void oracleInitialize(void) {
	OQS_init();
}

// Seeds the NIST AES-256 CTR DRBG of liboqs and makes it the random source.
void oracleUseNISTRandom(const uint8_t *entropy, const uint8_t *personalization) {
	releaseKATGenerator();
	OQS_randombytes_custom_algorithm(&OQS_randombytes_nist_kat);
	OQS_randombytes_nist_kat_init_256bit(entropy, personalization);
}

// Seeds the generator that the liboqs KAT programs use for an algorithm: the SHAKE256
// generator for HQC and the NIST DRBG for every other algorithm.
int oracleUseKATRandom(const char *methodName, const uint8_t *entropy, const uint8_t *personalization) {
	releaseKATGenerator();
	katGenerator = OQS_KAT_PRNG_new(methodName);
	if (katGenerator == NULL) {
		return OQS_ERROR;
	}
	OQS_KAT_PRNG_seed(katGenerator, entropy, personalization);
	return OQS_SUCCESS;
}

static void fillFromCallback(uint8_t *bytes, size_t length) {
	callbackFill(callbackContext, bytes, length);
}

// Makes a callback the random source, so that the C code reads its random bytes from Rust.
void oracleUseCallbackRandom(void (*fill)(void *, uint8_t *, size_t), void *context) {
	releaseKATGenerator();
	callbackFill = fill;
	callbackContext = context;
	OQS_randombytes_custom_algorithm(&fillFromCallback);
}

void oracleRandomBytes(uint8_t *bytes, size_t length) {
	OQS_randombytes(bytes, length);
}

void oracleFree(void *pointer) {
	OQS_MEM_insecure_free(pointer);
}

// Key encapsulation mechanisms.

size_t oracleKEMCount(void) {
	return (size_t)OQS_KEM_alg_count();
}

const char *oracleKEMIdentifier(size_t index) {
	return OQS_KEM_alg_identifier(index);
}

int oracleKEMIsEnabled(const char *name) {
	return OQS_KEM_alg_is_enabled(name);
}

int oracleKEMFacts(const char *name, OracleKEMFacts *facts) {
	OQS_KEM *kem = OQS_KEM_new(name);
	if (kem == NULL) {
		return OQS_ERROR;
	}
	facts->name = kem->method_name;
	facts->algorithmVersion = kem->alg_version;
	facts->claimedNISTLevel = kem->claimed_nist_level;
	facts->isINDCCASecure = kem->ind_cca ? 1 : 0;
	facts->publicKeyLength = kem->length_public_key;
	facts->secretKeyLength = kem->length_secret_key;
	facts->ciphertextLength = kem->length_ciphertext;
	facts->sharedSecretLength = kem->length_shared_secret;
	facts->keyPairSeedLength = kem->length_keypair_seed;
	facts->encapsulationSeedLength = kem->length_encaps_seed;
	OQS_KEM_free(kem);
	return OQS_SUCCESS;
}

int oracleKEMKeyPair(const char *name, uint8_t *publicKey, uint8_t *secretKey) {
	OQS_KEM *kem = OQS_KEM_new(name);
	if (kem == NULL) {
		return OQS_ERROR;
	}
	OQS_STATUS status = OQS_KEM_keypair(kem, publicKey, secretKey);
	OQS_KEM_free(kem);
	return status;
}

int oracleKEMKeyPairFromSeed(const char *name, uint8_t *publicKey, uint8_t *secretKey, const uint8_t *seed) {
	OQS_KEM *kem = OQS_KEM_new(name);
	if (kem == NULL) {
		return OQS_ERROR;
	}
	OQS_STATUS status = OQS_KEM_keypair_derand(kem, publicKey, secretKey, seed);
	OQS_KEM_free(kem);
	return status;
}

int oracleKEMEncapsulate(const char *name, uint8_t *ciphertext, uint8_t *sharedSecret, const uint8_t *publicKey) {
	OQS_KEM *kem = OQS_KEM_new(name);
	if (kem == NULL) {
		return OQS_ERROR;
	}
	OQS_STATUS status = OQS_KEM_encaps(kem, ciphertext, sharedSecret, publicKey);
	OQS_KEM_free(kem);
	return status;
}

int oracleKEMEncapsulateWithSeed(const char *name, uint8_t *ciphertext, uint8_t *sharedSecret, const uint8_t *publicKey, const uint8_t *seed) {
	OQS_KEM *kem = OQS_KEM_new(name);
	if (kem == NULL) {
		return OQS_ERROR;
	}
	OQS_STATUS status = OQS_KEM_encaps_derand(kem, ciphertext, sharedSecret, publicKey, seed);
	OQS_KEM_free(kem);
	return status;
}

int oracleKEMDecapsulate(const char *name, uint8_t *sharedSecret, const uint8_t *ciphertext, const uint8_t *secretKey) {
	OQS_KEM *kem = OQS_KEM_new(name);
	if (kem == NULL) {
		return OQS_ERROR;
	}
	OQS_STATUS status = OQS_KEM_decaps(kem, sharedSecret, ciphertext, secretKey);
	OQS_KEM_free(kem);
	return status;
}

// Signature schemes.

size_t oracleSignatureCount(void) {
	return (size_t)OQS_SIG_alg_count();
}

const char *oracleSignatureIdentifier(size_t index) {
	return OQS_SIG_alg_identifier(index);
}

int oracleSignatureIsEnabled(const char *name) {
	return OQS_SIG_alg_is_enabled(name);
}

int oracleSignatureFacts(const char *name, OracleSignatureFacts *facts) {
	OQS_SIG *sig = OQS_SIG_new(name);
	if (sig == NULL) {
		return OQS_ERROR;
	}
	facts->name = sig->method_name;
	facts->algorithmVersion = sig->alg_version;
	facts->claimedNISTLevel = sig->claimed_nist_level;
	facts->isEUFCMASecure = sig->euf_cma ? 1 : 0;
	facts->isSUFCMASecure = sig->suf_cma ? 1 : 0;
	facts->supportsContext = sig->sig_with_ctx_support ? 1 : 0;
	facts->publicKeyLength = sig->length_public_key;
	facts->secretKeyLength = sig->length_secret_key;
	facts->signatureLength = sig->length_signature;
	OQS_SIG_free(sig);
	return OQS_SUCCESS;
}

int oracleSignatureKeyPair(const char *name, uint8_t *publicKey, uint8_t *secretKey) {
	OQS_SIG *sig = OQS_SIG_new(name);
	if (sig == NULL) {
		return OQS_ERROR;
	}
	OQS_STATUS status = OQS_SIG_keypair(sig, publicKey, secretKey);
	OQS_SIG_free(sig);
	return status;
}

int oracleSign(const char *name, uint8_t *signature, size_t *signatureLength, const uint8_t *message, size_t messageLength, const uint8_t *secretKey) {
	OQS_SIG *sig = OQS_SIG_new(name);
	if (sig == NULL) {
		return OQS_ERROR;
	}
	OQS_STATUS status = OQS_SIG_sign(sig, signature, signatureLength, message, messageLength, secretKey);
	OQS_SIG_free(sig);
	return status;
}

int oracleSignWithContext(const char *name, uint8_t *signature, size_t *signatureLength, const uint8_t *message, size_t messageLength, const uint8_t *context, size_t contextLength, const uint8_t *secretKey) {
	OQS_SIG *sig = OQS_SIG_new(name);
	if (sig == NULL) {
		return OQS_ERROR;
	}
	OQS_STATUS status = OQS_SIG_sign_with_ctx_str(sig, signature, signatureLength, message, messageLength, context, contextLength, secretKey);
	OQS_SIG_free(sig);
	return status;
}

int oracleVerify(const char *name, const uint8_t *message, size_t messageLength, const uint8_t *signature, size_t signatureLength, const uint8_t *publicKey) {
	OQS_SIG *sig = OQS_SIG_new(name);
	if (sig == NULL) {
		return OQS_ERROR;
	}
	OQS_STATUS status = OQS_SIG_verify(sig, message, messageLength, signature, signatureLength, publicKey);
	OQS_SIG_free(sig);
	return status;
}

int oracleVerifyWithContext(const char *name, const uint8_t *message, size_t messageLength, const uint8_t *signature, size_t signatureLength, const uint8_t *context, size_t contextLength, const uint8_t *publicKey) {
	OQS_SIG *sig = OQS_SIG_new(name);
	if (sig == NULL) {
		return OQS_ERROR;
	}
	OQS_STATUS status = OQS_SIG_verify_with_ctx_str(sig, message, messageLength, signature, signatureLength, context, contextLength, publicKey);
	OQS_SIG_free(sig);
	return status;
}

// Stateful signature schemes. The secret key crosses to Rust in its serialized form.

typedef struct {
	uint8_t *bytes;
	size_t length;
} OracleStoredKey;

// The store callback of a secret key: it keeps a copy of the advanced key that liboqs persists
// before it releases a signature.
static OQS_STATUS storeSecretKey(uint8_t *secretKey, size_t length, void *context) {
	OracleStoredKey *stored = (OracleStoredKey *)context;
	OQS_MEM_insecure_free(stored->bytes);
	stored->bytes = OQS_MEM_malloc(length);
	if (stored->bytes == NULL) {
		stored->length = 0;
		return OQS_ERROR;
	}
	memcpy(stored->bytes, secretKey, length);
	stored->length = length;
	return OQS_SUCCESS;
}

size_t oracleStatefulCount(void) {
	return (size_t)OQS_SIG_STFL_alg_count();
}

const char *oracleStatefulIdentifier(size_t index) {
	return OQS_SIG_STFL_alg_identifier(index);
}

int oracleStatefulIsEnabled(const char *name) {
	return OQS_SIG_STFL_alg_is_enabled(name);
}

int oracleStatefulFacts(const char *name, OracleStatefulFacts *facts) {
	OQS_SIG_STFL *sig = OQS_SIG_STFL_new(name);
	if (sig == NULL) {
		return OQS_ERROR;
	}
	facts->objectIdentifier = sig->oid;
	facts->name = sig->method_name;
	facts->algorithmVersion = sig->alg_version;
	facts->isEUFCMASecure = sig->euf_cma ? 1 : 0;
	facts->isSUFCMASecure = sig->suf_cma ? 1 : 0;
	facts->publicKeyLength = sig->length_public_key;
	facts->secretKeyLength = sig->length_secret_key;
	facts->signatureLength = sig->length_signature;
	OQS_SIG_STFL_free(sig);
	return OQS_SUCCESS;
}

// Generates a key pair. The serialized secret key comes back in memory that oracleFree releases.
int oracleStatefulKeyPair(const char *name, uint8_t *publicKey, uint8_t **secretKey, size_t *secretKeyLength) {
	OQS_SIG_STFL *sig = OQS_SIG_STFL_new(name);
	OQS_SIG_STFL_SECRET_KEY *key = OQS_SIG_STFL_SECRET_KEY_new(name);
	OQS_STATUS status = OQS_ERROR;
	if (sig != NULL && key != NULL) {
		status = OQS_SIG_STFL_keypair(sig, publicKey, key);
		if (status == OQS_SUCCESS) {
			status = OQS_SIG_STFL_SECRET_KEY_serialize(secretKey, secretKeyLength, key);
		}
	}
	OQS_SIG_STFL_SECRET_KEY_free(key);
	OQS_SIG_STFL_free(sig);
	return status;
}

// Signs with a serialized secret key. The advanced key that liboqs persisted comes back in memory
// that oracleFree releases.
int oracleStatefulSign(const char *name, uint8_t *signature, size_t *signatureLength, const uint8_t *message, size_t messageLength, const uint8_t *secretKey, size_t secretKeyLength, uint8_t **advancedSecretKey, size_t *advancedSecretKeyLength) {
	OQS_SIG_STFL *sig = OQS_SIG_STFL_new(name);
	OQS_SIG_STFL_SECRET_KEY *key = OQS_SIG_STFL_SECRET_KEY_new(name);
	OracleStoredKey stored = {NULL, 0};
	OQS_STATUS status = OQS_ERROR;
	if (sig != NULL && key != NULL) {
		status = OQS_SIG_STFL_SECRET_KEY_deserialize(key, secretKey, secretKeyLength, &stored);
		if (status == OQS_SUCCESS) {
			OQS_SIG_STFL_SECRET_KEY_SET_store_cb(key, &storeSecretKey, &stored);
			status = OQS_SIG_STFL_sign(sig, signature, signatureLength, message, messageLength, key);
		}
	}
	if (status == OQS_SUCCESS && stored.bytes != NULL) {
		*advancedSecretKey = stored.bytes;
		*advancedSecretKeyLength = stored.length;
	} else {
		OQS_MEM_insecure_free(stored.bytes);
		if (status == OQS_SUCCESS) {
			status = OQS_ERROR;
		}
	}
	OQS_SIG_STFL_SECRET_KEY_free(key);
	OQS_SIG_STFL_free(sig);
	return status;
}

int oracleStatefulVerify(const char *name, const uint8_t *message, size_t messageLength, const uint8_t *signature, size_t signatureLength, const uint8_t *publicKey) {
	OQS_SIG_STFL *sig = OQS_SIG_STFL_new(name);
	if (sig == NULL) {
		return OQS_ERROR;
	}
	OQS_STATUS status = OQS_SIG_STFL_verify(sig, message, messageLength, signature, signatureLength, publicKey);
	OQS_SIG_STFL_free(sig);
	return status;
}

// Reads the remaining (isTotal 0) or total (isTotal 1) signature count of a serialized key.
int oracleStatefulSignatureCount(const char *name, const uint8_t *secretKey, size_t secretKeyLength, int isTotal, unsigned long long *count) {
	OQS_SIG_STFL *sig = OQS_SIG_STFL_new(name);
	OQS_SIG_STFL_SECRET_KEY *key = OQS_SIG_STFL_SECRET_KEY_new(name);
	OQS_STATUS status = OQS_ERROR;
	if (sig != NULL && key != NULL) {
		status = OQS_SIG_STFL_SECRET_KEY_deserialize(key, secretKey, secretKeyLength, NULL);
		if (status == OQS_SUCCESS) {
			status = isTotal ? OQS_SIG_STFL_sigs_total(sig, count, key) : OQS_SIG_STFL_sigs_remaining(sig, count, key);
		}
	}
	OQS_SIG_STFL_SECRET_KEY_free(key);
	OQS_SIG_STFL_free(sig);
	return status;
}

// LMS working keys. OQS_SIG_STFL_sign of LMS loads a working key of hash-sigs from the private key
// for each signature, which costs about one key generation. A working key here is loaded once and
// signs on from its last state. The serialized key lives in Rust: its first PRIVATE_KEY_LEN bytes
// are the private key, which each signature advances in place, as hss_advance_count advances the
// private key of liboqs, and the rest is the aux data, which a signature never changes.

// The memory that a working key may take. liboqs loads with a target of 0, which gives subtrees of
// a few levels. A larger target gives larger subtrees, so the working key crosses fewer subtree
// boundaries and loads again less often. The signatures are the same for any target.
#define WORKING_KEY_MEMORY_TARGET ((size_t)64 << 20)

// Loads a working key from a serialized secret key, with the aux data that the key carries. Returns
// NULL when hash-sigs refuses the key.
void *oracleLMSWorkingKeyLoad(uint8_t *secretKey, size_t secretKeyLength) {
	if (secretKeyLength < PRIVATE_KEY_LEN) {
		return NULL;
	}
	return hss_load_private_key(NULL, secretKey, WORKING_KEY_MEMORY_TARGET, secretKey + PRIVATE_KEY_LEN, secretKeyLength - PRIVATE_KEY_LEN, NULL);
}

void oracleLMSWorkingKeyFree(void *workingKey) {
	hss_free_working_key(workingKey);
}

// One signature with a working key: the steps of oqs_sig_stfl_lms_sign after its load of the
// working key. With no update function, hash-sigs advances the private key at secretKey in place.
static bool signWithWorkingKey(struct hss_working_key *workingKey, uint8_t *secretKey, uint8_t *signature, size_t signatureCapacity, size_t *signatureLength, const uint8_t *message, size_t messageLength) {
	if (workingKey == NULL) {
		return false;
	}
	size_t length = hss_get_signature_len_from_working_key(workingKey);
	if (length == 0 || length > signatureCapacity) {
		return false;
	}
	struct hss_sign_inc context;
	if (!hss_sign_init(&context, workingKey, NULL, secretKey, signature, length, NULL)) {
		return false;
	}
	(void)hss_sign_update(&context, message, messageLength);
	if (!hss_sign_finalize(&context, workingKey, signature, NULL)) {
		return false;
	}
	*signatureLength = length;
	return true;
}

// Signs a message with a working key and advances the serialized key in place.
//
// A working key of liboqs does not sign on correctly. The loop at the end of
// hss_generate_signature that moves a tree to its next subtree skips the top tree, and it marks the
// key as expired at the end of the first bottom tree. So a working key of one tree gives signatures
// that do not verify from its first subtree boundary on, and a working key of two trees fails at
// the end of its first bottom tree. OQS_SIG_STFL_sign never meets this, because it loads a new
// working key for each signature. So each signature of the working key is verified. When the
// signature fails or does not verify, the private key goes back to its state before the signature,
// the working key is loaded again from the serialized key, and the new working key makes the
// signature again, as the new working key of OQS_SIG_STFL_sign makes it.
int oracleLMSWorkingKeySign(const char *name, void **workingKey, uint8_t *secretKey, size_t secretKeyLength, const uint8_t *publicKey, uint8_t *signature, size_t *signatureLength, const uint8_t *message, size_t messageLength) {
	OQS_SIG_STFL *sig = OQS_SIG_STFL_new(name);
	if (sig == NULL || secretKeyLength < PRIVATE_KEY_LEN) {
		OQS_SIG_STFL_free(sig);
		return OQS_ERROR;
	}
	uint8_t privateKey[PRIVATE_KEY_LEN];
	memcpy(privateKey, secretKey, PRIVATE_KEY_LEN);
	bool isSigned = signWithWorkingKey(*workingKey, secretKey, signature, sig->length_signature, signatureLength, message, messageLength);
	if (!isSigned || OQS_SIG_STFL_verify(sig, message, messageLength, signature, *signatureLength, publicKey) != OQS_SUCCESS) {
		memcpy(secretKey, privateKey, PRIVATE_KEY_LEN);
		hss_free_working_key(*workingKey);
		*workingKey = oracleLMSWorkingKeyLoad(secretKey, secretKeyLength);
		isSigned = signWithWorkingKey(*workingKey, secretKey, signature, sig->length_signature, signatureLength, message, messageLength);
	}
	OQS_MEM_cleanse(privateKey, PRIVATE_KEY_LEN);
	OQS_SIG_STFL_free(sig);
	if (!isSigned) {
		*signatureLength = 0;
		return OQS_ERROR;
	}
	return OQS_SUCCESS;
}

// Reads the remaining (isTotal 0) or total (isTotal 1) signature count of a serialized key with a
// working key. OQS_SIG_STFL_lms_sigs_total loads a new working key for its max_count, and
// OQS_SIG_STFL_lms_sigs_left subtracts the count of the private key. This function takes the
// max_count of the loaded working key. It refuses a count above max_count, as the load of liboqs
// does. After the last signature, hash-sigs writes PARM_SET_END over the whole private key, so that
// count is above max_count too.
int oracleLMSWorkingKeySignatureCount(const void *workingKey, const uint8_t *secretKey, size_t secretKeyLength, int isTotal, unsigned long long *count) {
	const struct hss_working_key *working = workingKey;
	if (working == NULL || secretKeyLength < PRIVATE_KEY_LEN) {
		return OQS_ERROR;
	}
	sequence_t current = get_bigendian(secretKey + PRIVATE_KEY_INDEX, PRIVATE_KEY_INDEX_LEN);
	if (current > working->max_count) {
		return OQS_ERROR;
	}
	*count = isTotal ? (unsigned long long)working->max_count : (unsigned long long)(working->max_count - current);
	return OQS_SUCCESS;
}

// Primitives.

void oracleSHA3256(uint8_t *output, const uint8_t *input, size_t inputLength) {
	OQS_SHA3_sha3_256(output, input, inputLength);
}

void oracleSHA3384(uint8_t *output, const uint8_t *input, size_t inputLength) {
	OQS_SHA3_sha3_384(output, input, inputLength);
}

void oracleSHA3512(uint8_t *output, const uint8_t *input, size_t inputLength) {
	OQS_SHA3_sha3_512(output, input, inputLength);
}

void oracleSHAKE128(uint8_t *output, size_t outputLength, const uint8_t *input, size_t inputLength) {
	OQS_SHA3_shake128(output, outputLength, input, inputLength);
}

void oracleSHAKE256(uint8_t *output, size_t outputLength, const uint8_t *input, size_t inputLength) {
	OQS_SHA3_shake256(output, outputLength, input, inputLength);
}

// Absorbs the input in pieces of absorbStep bytes and squeezes the output in pieces of
// squeezeStep bytes, with the incremental API. A step of 0 means one piece.
void oracleSHAKE128InPieces(uint8_t *output, size_t outputLength, size_t squeezeStep, const uint8_t *input, size_t inputLength, size_t absorbStep) {
	OQS_SHA3_shake128_inc_ctx state;
	OQS_SHA3_shake128_inc_init(&state);
	for (size_t offset = 0; offset < inputLength;) {
		size_t piece = (absorbStep == 0 || inputLength - offset < absorbStep) ? inputLength - offset : absorbStep;
		OQS_SHA3_shake128_inc_absorb(&state, input + offset, piece);
		offset += piece;
	}
	OQS_SHA3_shake128_inc_finalize(&state);
	for (size_t offset = 0; offset < outputLength;) {
		size_t piece = (squeezeStep == 0 || outputLength - offset < squeezeStep) ? outputLength - offset : squeezeStep;
		OQS_SHA3_shake128_inc_squeeze(output + offset, piece, &state);
		offset += piece;
	}
	OQS_SHA3_shake128_inc_ctx_release(&state);
}

void oracleSHAKE256InPieces(uint8_t *output, size_t outputLength, size_t squeezeStep, const uint8_t *input, size_t inputLength, size_t absorbStep) {
	OQS_SHA3_shake256_inc_ctx state;
	OQS_SHA3_shake256_inc_init(&state);
	for (size_t offset = 0; offset < inputLength;) {
		size_t piece = (absorbStep == 0 || inputLength - offset < absorbStep) ? inputLength - offset : absorbStep;
		OQS_SHA3_shake256_inc_absorb(&state, input + offset, piece);
		offset += piece;
	}
	OQS_SHA3_shake256_inc_finalize(&state);
	for (size_t offset = 0; offset < outputLength;) {
		size_t piece = (squeezeStep == 0 || outputLength - offset < squeezeStep) ? outputLength - offset : squeezeStep;
		OQS_SHA3_shake256_inc_squeeze(output + offset, piece, &state);
		offset += piece;
	}
	OQS_SHA3_shake256_inc_ctx_release(&state);
}

void oracleSHA256(uint8_t *output, const uint8_t *input, size_t inputLength) {
	OQS_SHA2_sha256(output, input, inputLength);
}

void oracleSHA384(uint8_t *output, const uint8_t *input, size_t inputLength) {
	OQS_SHA2_sha384(output, input, inputLength);
}

void oracleSHA512(uint8_t *output, const uint8_t *input, size_t inputLength) {
	OQS_SHA2_sha512(output, input, inputLength);
}

void oracleAES128ECB(uint8_t *ciphertext, const uint8_t *plaintext, size_t length, const uint8_t *key) {
	OQS_AES128_ECB_enc(plaintext, length, key, ciphertext);
}

void oracleAES256ECB(uint8_t *ciphertext, const uint8_t *plaintext, size_t length, const uint8_t *key) {
	OQS_AES256_ECB_enc(plaintext, length, key, ciphertext);
}

void oracleAES128CounterStream(uint8_t *output, size_t outputLength, const uint8_t *iv, size_t ivLength, const uint8_t *key) {
	void *schedule = NULL;
	OQS_AES128_CTR_inc_init(key, &schedule);
	OQS_AES128_CTR_inc_stream_iv(iv, ivLength, schedule, output, outputLength);
	OQS_AES128_free_schedule(schedule);
}

void oracleAES256CounterStream(uint8_t *output, size_t outputLength, const uint8_t *iv, size_t ivLength, const uint8_t *key) {
	void *schedule = NULL;
	OQS_AES256_CTR_inc_init(key, &schedule);
	OQS_AES256_CTR_inc_stream_iv(iv, ivLength, schedule, output, outputLength);
	OQS_AES256_free_schedule(schedule);
}

// The bitsliced Rijndael-256 of MQOM. liboqs has no public API for the cipher, so the shim
// declares the context of `rijndael_ct64.h` and two functions that the MQOM code exports from
// `liboqs.a`. Each MQOM set compiles the same `rijndael_ct64.c`, and these are the names of the
// set `mqom2_cat5_gf16_fast_r3`.
typedef struct {
	int type;
	uint32_t roundCount;
	uint32_t keyWordCount;
	uint32_t blockWordCount;
	uint32_t roundKeys[120];
} OracleRijndael256Context;

int oqs_sig_private_mqom2_cat5_gf16_fast_r3_default_rijndael256_ct64_setkey_enc(OracleRijndael256Context *context, const uint8_t key[32]);
int oqs_sig_private_mqom2_cat5_gf16_fast_r3_default_rijndael256_ct64_enc(const OracleRijndael256Context *context, const uint8_t plaintext[32], uint8_t ciphertext[32]);

void oracleRijndael256ECB(uint8_t *ciphertext, const uint8_t *plaintext, size_t length, const uint8_t *key) {
	OracleRijndael256Context context;
	oqs_sig_private_mqom2_cat5_gf16_fast_r3_default_rijndael256_ct64_setkey_enc(&context, key);
	for (size_t offset = 0; offset + 32 <= length; offset += 32) {
		oqs_sig_private_mqom2_cat5_gf16_fast_r3_default_rijndael256_ct64_enc(&context, plaintext + offset, ciphertext + offset);
	}
}

// Streams whole blocks in two calls from one counter, so that the second call continues the
// counter of the first.
void oracleAES256CounterBlocksTwice(uint8_t *output, size_t firstBlocks, size_t secondBlocks, const uint8_t *iv, size_t ivLength, const uint8_t *key) {
	void *schedule = NULL;
	OQS_AES256_CTR_inc_init(key, &schedule);
	OQS_AES256_CTR_inc_iv(iv, ivLength, schedule);
	OQS_AES256_CTR_inc_stream_blks(schedule, output, firstBlocks);
	OQS_AES256_CTR_inc_stream_blks(schedule, output + 16 * firstBlocks, secondBlocks);
	OQS_AES256_free_schedule(schedule);
}
