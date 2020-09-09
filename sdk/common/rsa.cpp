#include <stdint.h>
#include <string>

#include "openssl/err.h"
#include "openssl/pem.h"
#include "openssl/rand.h"
#include "openssl/rsa.h"
#include "openssl/sha.h"

#include "tee/common/bytes.h"
#include "tee/common/error.h"
#include "tee/common/log.h"
#include "tee/common/rsa.h"
#include "tee/common/type.h"

namespace tee {
namespace common {

TeeErrorCode RsaCrypto::GetKeyFromRSA(bool is_public_key, std::string* key,
                                      const RSA_ptr& rsa_ptr) {
  BIO_ptr bio(BIO_new(BIO_s_mem()), BIO_free_all);
  if (!bio) {
    ELOG_ERROR("Failed to new BIO");
    return TEE_ERROR_UNEXPECTED;
  }

  int res = 0;
  if (is_public_key) {
    res = PEM_write_bio_RSAPublicKey(bio.get(), rsa_ptr.get());
  } else {
    res = PEM_write_bio_RSAPrivateKey(bio.get(), rsa_ptr.get(), NULL, NULL, 0,
                                      0, NULL);
  }
  if (!res) {
    ELOG_ERROR("Failed to write bio RSA Key");
    return TEE_ERROR_UNEXPECTED;
  }

  int keylen = BIO_pending(bio.get());
  DataBytes pem_str(keylen);
  if (!BIO_read(bio.get(), pem_str.data(), keylen)) {
    ELOG_ERROR("Failed to read BIO");
    return TEE_ERROR_UNEXPECTED;
  }
  key->assign(RCAST(char*, pem_str.data()), keylen);
  return TEE_SUCCESS;
}

TeeErrorCode RsaCrypto::GetRSAFromKey(const bool is_public_key,
                                      const std::string& key,
                                      RSA_ptr* rsa_ptr) {
  void* pkey = RCAST(void*, CCAST(char*, key.c_str()));
  BIO_ptr bio(BIO_new_mem_buf(pkey, -1), BIO_free_all);
  if (!bio) {
    ELOG_ERROR("Failed to new BIO memory buffer");
    return TEE_ERROR_UNEXPECTED;
  }

  RSA* rsa = NULL;
  if (is_public_key) {
    rsa = PEM_read_bio_RSAPublicKey(bio.get(), NULL, NULL, NULL);
  } else {
    rsa = PEM_read_bio_RSAPrivateKey(bio.get(), NULL, NULL, NULL);
  }
  rsa_ptr->reset(rsa);
  if (!rsa) {
    ELOG_ERROR("Failed to read PEM key");
    return TEE_ERROR_UNEXPECTED;
  }

  return TEE_SUCCESS;
}

TeeErrorCode RsaCrypto::GenerateKeyPair(std::string* public_key,
                                        std::string* private_key) {
  uint64_t e = RSA_F4;
  BIGNUM_ptr exp(BN_new(), BN_free);
  if (!exp) {
    ELOG_ERROR("Failed to new big number");
    return TEE_ERROR_UNEXPECTED;
  }
  if (!BN_set_word(exp.get(), e)) {
    ELOG_ERROR("Failed to set word");
    return TEE_ERROR_UNEXPECTED;
  }

  RSA_ptr rsa_ptr(RSA_new(), RSA_free);
  if (!rsa_ptr) {
    ELOG_ERROR("Failed to new RSA");
    return TEE_ERROR_UNEXPECTED;
  }
  if (!RSA_generate_key_ex(rsa_ptr.get(), kRSAKeySize, exp.get(), NULL)) {
    ELOG_ERROR("Failed to generate RSA key");
    return TEE_ERROR_UNEXPECTED;
  }

  TeeErrorCode ret = GetKeyFromRSA(kIsPublicKey, public_key, rsa_ptr);
  if (ret != TEE_SUCCESS) {
    ELOG_ERROR_TRACE();
    return ret;
  }
  ret = GetKeyFromRSA(kIsPrivateKey, private_key, rsa_ptr);
  if (ret != TEE_SUCCESS) {
    ELOG_ERROR_TRACE();
    return ret;
  }

  return TEE_SUCCESS;
}

TeeErrorCode RsaCrypto::Encrypt(const std::string& public_key,
                                const std::string& src, std::string* dst) {
  if (dst == NULL || public_key.empty() || src.empty()) {
    ELOG_ERROR("Invalid public key for RSA encrypt");
    return TEE_ERROR_INVALID_PARAMETER;
  }

  dst->clear();
  std::string buffer;
  size_t pos = 0;
  size_t length = src.length();
  size_t step = GetMaxEncryptBufferSize();
  TeeErrorCode ret = TEE_ERROR_INVALID_PARAMETER;
  while (pos < length) {
    size_t enc_len = (pos + step) <= length ? step : (length - pos);
    ret = RSAEncrypt(public_key, src.substr(pos, enc_len), &buffer);
    if (ret != TEE_SUCCESS) {
      ELOG_ERROR_TRACE();
      break;
    }
    pos += step;
    dst->append(buffer);
  }
  return ret;
}

TeeErrorCode RsaCrypto::Decrypt(const std::string& private_key,
                                const std::string& src, std::string* dst) {
  if (dst == NULL || private_key.empty() || src.empty() ||
      src.length() % kRSAEncryptedTextLength != 0) {
    ELOG_ERROR("Invalid input, src length = %ld", src.length());
    return TEE_ERROR_PARAMETERS;
  }

  dst->clear();
  std::string buffer;
  size_t pos = 0;
  size_t length = src.length();
  size_t step = GetDecryptBufferSize();
  TeeErrorCode ret = TEE_ERROR_PARAMETERS;
  while (pos < length) {
    size_t dec_len = (pos + step) <= length ? step : (length - pos);
    ret = RSADecrypt(private_key, src.substr(pos, dec_len), &buffer);
    if (ret != TEE_SUCCESS) {
      ELOG_ERROR("Fail to do RSA decryption");
      break;
    }
    pos += step;
    dst->append(buffer);
  }
  return ret;
}

TeeErrorCode RsaCrypto::Sign(const std::string& private_key,
                             const std::string& msg, std::string* sigret) {
  if (sigret == NULL || private_key.empty() || msg.empty()) {
    ELOG_ERROR("Invalid private key for RSA sign");
    return TEE_ERROR_INVALID_PARAMETER;
  }

  RSA_ptr rsa_ptr(NULL, RSA_free);
  TeeErrorCode ret = GetRSAFromKey(kIsPrivateKey, private_key, &rsa_ptr);
  if (ret != TEE_SUCCESS) {
    ELOG_ERROR_TRACE();
    return ret;
  }

  DataBytes signature(RSA_size(rsa_ptr.get()));
  DataBytes msg_hash(msg);
  msg_hash.ToSHA256();
  unsigned int sign_size = 0;
  int rsa_ret = RSA_sign(NID_sha256, msg_hash.data(), msg_hash.size(),
                         signature.data(), &sign_size, rsa_ptr.get());
  if (rsa_ret != OPENSSL_SUCCESS) {  // RSA_sign() returns 1 on success
    ERR_load_crypto_strings();
    char error_msg[kErrorBufferLength] = {};
    ERR_error_string(ERR_get_error(), error_msg);
    ELOG_ERROR("Failed to do RSA sign: %s", error_msg);
    return TEE_ERROR_CRYPTO_RSA_SIGN;
  }
  sigret->assign(RCAST(char*, signature.data()), sign_size);
  return TEE_SUCCESS;
}

TeeErrorCode RsaCrypto::Verify(const std::string& public_key,
                               const std::string& msg,
                               const std::string& sigbuf) {
  if (public_key.empty() || msg.empty() || sigbuf.empty()) {
    ELOG_ERROR("Invalid public key for RSA verify");
    return TEE_ERROR_PARAMETERS;
  }

  RSA_ptr rsa_ptr(NULL, RSA_free);
  // RSA_free() frees the RSA structure and its components.
  // The key is erased before the memory is returned to the system.
  // If rsa is a NULL pointer, no action occurs.
  TeeErrorCode ret = GetRSAFromKey(kIsPublicKey, public_key, &rsa_ptr);
  if (ret != TEE_SUCCESS) {
    return ret;
  }

  DataBytes msg_hash(msg);
  msg_hash.ToSHA256();
  int rsa_ret = RSA_verify(NID_sha256, msg_hash.data(), msg_hash.size(),
                           RCAST(const uint8_t*, sigbuf.data()),
                           SCAST(uint32_t, sigbuf.length()), rsa_ptr.get());
  if (rsa_ret != OPENSSL_SUCCESS) {
    ERR_load_crypto_strings();
    char error_msg[kErrorBufferLength] = {};
    ERR_error_string(ERR_get_error(), error_msg);
    ELOG_ERROR("Failed to do RSA verify: %s", error_msg);
    return TEE_ERROR_CRYPTO_RSA_VERIFY;
  }

  return TEE_SUCCESS;
}

TeeErrorCode RsaCrypto::RSAEncrypt(const std::string& public_key,
                                   const std::string& src, std::string* dst) {
  if (dst == NULL || public_key.empty() || src.empty() ||
      src.length() > kRSAPlainTextLength) {
    ELOG_ERROR("Invalid public key for RSAEncrypt");
    return TEE_ERROR_INVALID_PARAMETER;
  }

  RSA_ptr rsa_ptr(NULL, RSA_free);
  // RSA_free() frees the RSA structure and its components.
  // The key is erased before the memory is returned to the system.
  // If rsa is a NULL pointer, no action occurs.
  TeeErrorCode ret = GetRSAFromKey(kIsPublicKey, public_key, &rsa_ptr);
  if (ret != TEE_SUCCESS) {
    ELOG_ERROR_TRACE();
    return ret;
  }

  DataBytes ctext(RSA_size(rsa_ptr.get()));
  int ctext_len = RSA_public_encrypt(
      SCAST(int, src.length()), RCAST(const unsigned char*, src.data()),
      ctext.data(), rsa_ptr.get(), kRSAPaddingScheme);
  if (ctext_len == -1) {
    ERR_load_crypto_strings();
    char error_msg[kErrorBufferLength] = {};
    ERR_error_string(ERR_get_error(), error_msg);
    ELOG_ERROR("Failed to do RSA decryption: %s", error_msg);
    return TEE_ERROR_CRYPTO_RSA_ENCRYPT;
  }
  dst->assign(RCAST(char*, ctext.data()), ctext.size());
  return TEE_SUCCESS;
}

TeeErrorCode RsaCrypto::RSADecrypt(const std::string& private_key,
                                   const std::string& src, std::string* dst) {
  if (dst == NULL || private_key.empty() || src.empty() ||
      src.length() != kRSAEncryptedTextLength) {
    ELOG_ERROR("Invalid private key for RSA decryption");
    return TEE_ERROR_INVALID_PARAMETER;
  }

  RSA_ptr rsa_ptr(NULL, RSA_free);
  TeeErrorCode ret = GetRSAFromKey(kIsPrivateKey, private_key, &rsa_ptr);
  if (ret != TEE_SUCCESS) {
    ELOG_ERROR_TRACE();
    return ret;
  }

  DataBytes ptext(RSA_size(rsa_ptr.get()));
  int ptext_len = RSA_private_decrypt(
      SCAST(int, src.length()), RCAST(const unsigned char*, src.data()),
      ptext.data(), rsa_ptr.get(), kRSAPaddingScheme);
  if (ptext_len == -1) {
    ERR_load_crypto_strings();
    char error_msg[kErrorBufferLength] = {};
    ERR_error_string(ERR_get_error(), error_msg);
    ELOG_ERROR("Failed to do RSA decryption: %s", error_msg);
    return TEE_ERROR_CRYPTO_RSA_DECRYPT;
  }
  ptext.resize(ptext_len);
  dst->assign(RCAST(char*, ptext.data()), ptext_len);
  return TEE_SUCCESS;
}

int RsaCrypto::GetDecryptBufferSize() {
  return kRSAEncryptedTextLength;
}

int RsaCrypto::GetMaxEncryptBufferSize() {
  return kRSAPlainTextLength;
}

}  // namespace common
}  // namespace tee
