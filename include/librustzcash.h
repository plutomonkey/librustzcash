#ifndef LIBRUSTZCASH_INCLUDE_H_
#define LIBRUSTZCASH_INCLUDE_H_

#include <stdint.h>

extern "C" {
    uint64_t librustzcash_xor(uint64_t a, uint64_t b);
    bool librustzcash_eh_isvalid(uint32_t n,
                                 uint32_t k,
                                 const unsigned char* input,
                                 size_t input_len,
                                 const unsigned char* nonce,
                                 size_t nonce_len,
                                 uint32_t* indices,
                                 size_t indices_len);
}

#endif // LIBRUSTZCASH_INCLUDE_H_
