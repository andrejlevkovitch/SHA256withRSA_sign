// main.cpp

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

int main(int argc, char *argv[]) {
  if (argc != 2) {
    std::cerr << "you must set rsa key file as first arg" << std::endl;
    return EXIT_FAILURE;
  }

  std::filesystem::path rsaFile = argv[1];

  if (std::filesystem::is_regular_file(rsaFile) == false) {
    std::cerr << "invalid rsa file" << std::endl;
    return EXIT_FAILURE;
  }

  std::string   rsaKey;
  std::ifstream fin{rsaFile, std::ios::in};
  if (fin.is_open() == false) {
    std::cerr << "can not open rsa key file" << std::endl;
    return EXIT_FAILURE;
  }

  std::copy(std::istreambuf_iterator<char>{fin},
            std::istreambuf_iterator<char>{},
            std::back_inserter(rsaKey));

  std::string input;
  std::copy(std::istreambuf_iterator<char>{std::cin},
            std::istreambuf_iterator<char>{},
            std::back_inserter(input));
  if (input.empty()) {
    std::cerr << "invalid input" << std::endl;
    return EXIT_FAILURE;
  }

  EVP_MD_CTX *ctx = EVP_MD_CTX_create();
  if (EVP_DigestInit(ctx, EVP_sha256()) != 1) {
    std::cerr << "invlaid sha256" << std::endl;
    return EXIT_FAILURE;
  }
  if (EVP_DigestUpdate(ctx, input.data(), input.size()) != 1) {
    std::cerr << "invlaid sha256" << std::endl;
    return EXIT_FAILURE;
  }
  std::string digest;
  digest.resize(EVP_MD_size(EVP_sha256()));
  if (EVP_DigestFinal(ctx,
                      reinterpret_cast<unsigned char *>(digest.data()),
                      nullptr) != 1) {
    std::cerr << "invlaid sha256" << std::endl;
    return EXIT_FAILURE;
  }
  EVP_MD_CTX_free(ctx);

  BIO *buf = BIO_new_mem_buf(rsaKey.c_str(), rsaKey.size());
  RSA *rsa = PEM_read_bio_RSAPrivateKey(buf, nullptr, nullptr, nullptr);
  BIO_free(buf);

  if (rsa == nullptr) {
    std::cerr << "invalid pem private file" << std::endl;
    return EXIT_FAILURE;
  }

  std::string sigret;
  sigret.resize(RSA_size(rsa));
  unsigned int size = 0;
  if (RSA_sign(NID_sha256,
               reinterpret_cast<unsigned char *>(digest.data()),
               sizeof(digest),
               reinterpret_cast<unsigned char *>(sigret.data()),
               &size,
               rsa) != 1) {
    std::cerr << "invalid sign" << std::endl;
    RSA_free(rsa);
    return EXIT_FAILURE;
  }

  RSA_free(rsa);

  if (sigret.empty() || sigret.size() != size) {
    std::cerr << "invalid output" << std::endl;
    return EXIT_FAILURE;
  }

  std::cout << sigret;

  return EXIT_SUCCESS;
}
