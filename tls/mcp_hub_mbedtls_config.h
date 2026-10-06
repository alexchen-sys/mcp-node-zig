/* mbedTLS configuration for the mcp-node hub TLS server, TLS 1.3 only.
 *
 * Only what the hub needs: an ephemeral key exchange with AES-128/256-GCM
 * or ChaCha20-Poly1305, the hub's own certificate chain and private key
 * from PEM files, and PSA as the crypto backend (mandatory for TLS 1.3 in
 * mbedTLS 3.6). No client authentication at the TLS layer: the link
 * protocol authenticates nodes itself after the transport is up. */
#ifndef MCP_HUB_MBEDTLS_CONFIG_H
#define MCP_HUB_MBEDTLS_CONFIG_H

/* Platform: PEM files come from the filesystem; threads need PSA locking. */
#define MBEDTLS_FS_IO
#define MBEDTLS_THREADING_C
#define MBEDTLS_THREADING_ALT

/* check_config.h makes PLATFORM_C mandatory on Windows; mingw also
 * auto-defines MBEDTLS_PLATFORM_SNPRINTF_ALT, which requires it. */
#if defined(_WIN32)
#define MBEDTLS_PLATFORM_C
#endif

/* Crypto primitives. With no MBEDTLS_PSA_CRYPTO_CONFIG, PSA derives its
 * algorithm set from these legacy symbols. */
#define MBEDTLS_AES_C
#define MBEDTLS_GCM_C
#define MBEDTLS_CHACHA20_C
#define MBEDTLS_CHACHAPOLY_C
#define MBEDTLS_POLY1305_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA512_C /* also builds SHA-384 */
#define MBEDTLS_MD_C
#define MBEDTLS_HKDF_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_RSA_C
#define MBEDTLS_PKCS1_V21 /* TLS 1.3 RSA signatures are RSA-PSS */
#define MBEDTLS_ECP_C
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED
#define MBEDTLS_ECP_DP_CURVE25519_ENABLED
#define MBEDTLS_ECP_NIST_OPTIM
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECDSA_C

/* PSA is mandatory for TLS 1.3 in mbedTLS 3.6. */
#define MBEDTLS_PSA_CRYPTO_C
#define MBEDTLS_USE_PSA_CRYPTO

/* PSA's internal random generator. */
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_CTR_DRBG_C

/* Keys and certificates. */
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_OID_C
#define MBEDTLS_PEM_PARSE_C
#define MBEDTLS_BASE64_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_PK_PARSE_EC_EXTENDED /* SEC1 "EC PRIVATE KEY" blocks */
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C

/* TLS 1.3, server side only. */
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_SRV_C
#define MBEDTLS_SSL_PROTO_TLS1_3
/* Middlebox compatibility mode: send a dummy ChangeCipherSpec after
 * ServerHello. Some TLS 1.3 clients (Zig std among them) only switch to
 * decrypting handshake records when that record arrives. */
#define MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
/* check_config.h requires keeping the peer cert for TLS 1.3. */
#define MBEDTLS_SSL_KEEP_PEER_CERTIFICATE
/* TLS 1.3 ephemeral key exchange: the mode every certificate-based
 * handshake runs in (PSK modes stay off). */
#define MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED

/* Readable error strings for the hub log. */
#define MBEDTLS_ERROR_C

#endif /* MCP_HUB_MBEDTLS_CONFIG_H */
