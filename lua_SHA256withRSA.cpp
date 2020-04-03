// lua_SHA256withRSA.cpp
/**\file return function for get signature of message
 */

#include <cstdlib>
#include <lua.hpp>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <string>

extern "C" {
/**\brief in lua the function get two arguments: rsa private key and message.
 * Return string with signature of message
 */
static int lua_SHA256withRSA(lua_State *state) {
  const char * rsaKey        = luaL_checkstring(state, 1);
  const char * message       = luaL_checkstring(state, 2);
  unsigned int rsaKeyLength  = lua_strlen(state, 1);
  unsigned int messageLength = lua_strlen(state, 2);

  EVP_MD_CTX *ctx = EVP_MD_CTX_create();
  if (EVP_DigestInit(ctx, EVP_sha256()) != 1) {
    return luaL_error(state, "couldn't initialize sha256");
  }
  if (EVP_DigestUpdate(ctx, message, messageLength) != 1) {
    return luaL_error(state, "couldn't initialize sha256");
  }
  std::string digest;
  digest.resize(EVP_MD_size(EVP_sha256()));
  if (EVP_DigestFinal(ctx,
                      reinterpret_cast<unsigned char *>(digest.data()),
                      nullptr) != 1) {
    return luaL_error(state, "couldn't initialize sha256");
  }
  EVP_MD_CTX_free(ctx);

  BIO *buf = BIO_new_mem_buf(rsaKey, rsaKeyLength);
  RSA *rsa = PEM_read_bio_RSAPrivateKey(buf, nullptr, nullptr, nullptr);
  BIO_free(buf);

  if (rsa == nullptr) {
    return luaL_error(state, "invalid pem key");
  }

  std::string sigret;
  sigret.resize(RSA_size(rsa));
  unsigned int size = 0;
  if (RSA_sign(NID_sha256,
               reinterpret_cast<unsigned char *>(digest.data()),
               sizeof(digest),
               reinterpret_cast<unsigned char *>(sigret.data()),
               &size,
               rsa) != 1 ||
      sigret.empty() || sigret.size() != size) {
    RSA_free(rsa);
    return luaL_error(state, "invalid signature");
  }

  RSA_free(rsa);

  lua_pushlstring(state, sigret.data(), sigret.size());
  return 1;
}

int luaopen_SHA256withRSA(lua_State *state) {
  lua_pushcfunction(state, lua_SHA256withRSA);
  return 1;
}
}
