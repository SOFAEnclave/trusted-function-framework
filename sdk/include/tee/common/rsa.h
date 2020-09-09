#ifndef SDK_INCLUDE_TEE_COMMON_RSA_H_
#define SDK_INCLUDE_TEE_COMMON_RSA_H_

#include <stdint.h>
#include <memory>
#include <string>
#include <vector>

#include "openssl/rsa.h"  // RSA_PKCS1_OAEP_PADDING
#include "tee/common/error.h"

constexpr bool kIsPublicKey = true;
constexpr bool kIsPrivateKey = false;
constexpr char kRsaKeypairSeparator[] = "-----BEGIN RSA PRIVATE KEY-----";
constexpr char kRsaPubKeyEnd[] = "-----END RSA PUBLIC KEY-----";

namespace tee {
namespace common {

// Typedefs for memory management
// Specify type and destroy function type for unique_ptrs
typedef std::unique_ptr<BIO, void (*)(BIO*)> BIO_ptr;
typedef std::unique_ptr<BIGNUM, void (*)(BIGNUM*)> BIGNUM_ptr;
typedef std::unique_ptr<RSA, void (*)(RSA*)> RSA_ptr;

class RsaCrypto {
 public:
  /// @brief Generate RSA key pair
  ///
  /// Generate public key and private key in PEM format.
  ///
  /// @param public_key
  /// @param private_key
  ///
  /// @return TEE_SUCCESS on success
  static TeeErrorCode GenerateKeyPair(std::string* public_key,
                                      std::string* private_key);

  /// @brief Encrypt
  ///
  /// @param public_key
  /// @param src
  /// @param dst, dst.length() will be the multiples of kRSAEncryptedTextLength.
  ///
  /// @return TEE_SUCCESS on success
  static TeeErrorCode Encrypt(const std::string& public_key,
                              const std::string& src, std::string* dst);

  /// @brief Decrypt
  ///
  /// @param private_key
  /// @param src, src.length() should be the multiples of
  /// kRSAEncryptedTextLength
  /// @param dst
  ///
  /// @return TEE_SUCCESS on success
  static TeeErrorCode Decrypt(const std::string& private_key,
                              const std::string& src, std::string* dst);

  /// @brief Sign
  ///
  /// @param private_key
  /// @param msg, the input message to be signed
  /// @param sigret, return the signature.
  /// @parem digest_type
  ///
  /// @return TEE_SUCCESS on success
  static TeeErrorCode Sign(const std::string& private_key,
                           const std::string& msg, std::string* sigret);

  /// @brief Verify
  ///
  /// @param public_key
  /// @param msg, the input message to be signed
  /// @param sigbuf, signature data
  /// @param digest_type
  ///
  /// @return TEE_SUCCESS on success
  static TeeErrorCode Verify(const std::string& public_key,
                             const std::string& msg, const std::string& sigbuf);

  /// @brief get_pem_public_key_size
  ///
  /// @param void
  ///
  /// @return the max size of buffer which is used to save pem type public key.
  static size_t get_pem_public_key_size() {
    return kPubKeyPemSize;
  }

 private:
  // TODO(junxian) USE 3072 for long term security
  // Inside enclave, With every doubling of the RSA key length,
  // decryption is 6-7 times times slower
  static const size_t kPubKeyPemSize = 4096;
  static const int kRSAKeySize = 2048;
  static const int kRSAPaddingSize = 41;
  static const int kRSAPaddingScheme = RSA_PKCS1_OAEP_PADDING;
  static const int kRSAPlainTextLength = 214;
  static constexpr int kRSAEncryptedTextLength = (kRSAKeySize / 8);
  static constexpr int kRSASignatureLength = (kRSAKeySize / 8);
  // OpenSSL Error string buffer size
  // ERR_error_string() generates a human-readable string
  // representing the error code e, and places it at buf.
  // buf must be at least 120 bytes long.
  // https://www.openssl.org/docs/man1.0.2/man3/ERR_error_string.html */
  static const int kErrorBufferLength = 128;

  static TeeErrorCode GetKeyFromRSA(bool is_public_key, std::string* key,
                                    const RSA_ptr& rsa_ptr);
  static TeeErrorCode GetRSAFromKey(bool is_public_key, const std::string& key,
                                    RSA_ptr* rsa_ptr);

  /// @brief RSAEncrypt
  ///
  /// @param public_key
  /// @param src, src.length() should less than kRSAPlainTextLength
  /// @param dst, dst.length() should equal to kRSAEncryptedTextLength
  ///
  /// @return OASIS_SUCCESS on success
  static TeeErrorCode RSAEncrypt(const std::string& public_key,
                                 const std::string& src, std::string* dst);

  /// @brief RSADecrypt
  ///
  /// @param private_key
  /// @param src, src.length() should equal to kRSAEncryptedTextLength
  /// @param dst, dst.length() should less than kRSAPlainTextLength
  ///
  /// @return OASIS_SUCCESS on success
  static TeeErrorCode RSADecrypt(const std::string& private_key,
                                 const std::string& src, std::string* dst);
  /// @brief GetDecryptBufferSize
  ///
  /// @param
  ///
  /// @return Decrypt buffer size
  static int GetDecryptBufferSize();

  /// @brief GetMaxEncryptBufferSize
  ///
  /// @param
  ///
  /// @return Max encrypt buffer size
  static int GetMaxEncryptBufferSize();
};

}  // namespace common
}  // namespace tee

#endif  // SDK_INCLUDE_TEE_COMMON_RSA_H_
