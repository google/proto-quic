# This file contains source lists that are also consumed by
# generate_build_files.py.
#
# TODO(davidben): Move the other source lists into this file.

set(
  CRYPTO_TEST_DATA

  crypto/cipher_extra/test/aes_128_cbc_sha1_ssl3_tests.txt
  crypto/cipher_extra/test/aes_128_cbc_sha1_tls_implicit_iv_tests.txt
  crypto/cipher_extra/test/aes_128_cbc_sha1_tls_tests.txt
  crypto/cipher_extra/test/aes_128_cbc_sha256_tls_tests.txt
  crypto/cipher_extra/test/aes_128_ctr_hmac_sha256.txt
  crypto/cipher_extra/test/aes_128_gcm_siv_tests.txt
  crypto/cipher_extra/test/aes_128_gcm_tests.txt
  crypto/cipher_extra/test/aes_256_cbc_sha1_ssl3_tests.txt
  crypto/cipher_extra/test/aes_256_cbc_sha1_tls_implicit_iv_tests.txt
  crypto/cipher_extra/test/aes_256_cbc_sha1_tls_tests.txt
  crypto/cipher_extra/test/aes_256_cbc_sha256_tls_tests.txt
  crypto/cipher_extra/test/aes_256_cbc_sha384_tls_tests.txt
  crypto/cipher_extra/test/aes_256_ctr_hmac_sha256.txt
  crypto/cipher_extra/test/aes_256_gcm_siv_tests.txt
  crypto/cipher_extra/test/aes_256_gcm_tests.txt
  crypto/cipher_extra/test/chacha20_poly1305_tests.txt
  crypto/cipher_extra/test/cipher_tests.txt
  crypto/cipher_extra/test/des_ede3_cbc_sha1_ssl3_tests.txt
  crypto/cipher_extra/test/des_ede3_cbc_sha1_tls_implicit_iv_tests.txt
  crypto/cipher_extra/test/des_ede3_cbc_sha1_tls_tests.txt
  crypto/cipher_extra/test/nist_cavp/aes_128_cbc.txt
  crypto/cipher_extra/test/nist_cavp/aes_128_ctr.txt
  crypto/cipher_extra/test/nist_cavp/aes_128_gcm.txt
  crypto/cipher_extra/test/nist_cavp/aes_192_cbc.txt
  crypto/cipher_extra/test/nist_cavp/aes_192_ctr.txt
  crypto/cipher_extra/test/nist_cavp/aes_256_cbc.txt
  crypto/cipher_extra/test/nist_cavp/aes_256_ctr.txt
  crypto/cipher_extra/test/nist_cavp/aes_256_gcm.txt
  crypto/cipher_extra/test/nist_cavp/tdes_cbc.txt
  crypto/cipher_extra/test/nist_cavp/tdes_ecb.txt
  crypto/curve25519/ed25519_tests.txt
  crypto/ecdh/ecdh_tests.txt
  crypto/evp/evp_tests.txt
  crypto/evp/scrypt_tests.txt
  crypto/fipsmodule/aes/aes_tests.txt
  crypto/fipsmodule/bn/bn_tests.txt
  crypto/fipsmodule/ec/p256-x86_64_tests.txt
  crypto/fipsmodule/ecdsa/ecdsa_sign_tests.txt
  crypto/fipsmodule/ecdsa/ecdsa_verify_tests.txt
  crypto/fipsmodule/modes/gcm_tests.txt
  crypto/fipsmodule/rand/ctrdrbg_vectors.txt
  crypto/hmac_extra/hmac_tests.txt
  crypto/poly1305/poly1305_tests.txt
)
