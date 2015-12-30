#include <volk_sha256/volk_sha256.h>
#include <inttypes.h>
#include <iostream>
#include <string.h>
#include <stdio.h>

int main(){
    // Init
    char msg_char[] = "abcd";
    std::cout << "Message (char): " << msg_char << std::endl;

    size_t msg_len = strlen(msg_char);
    std::cout << "Message length: " << msg_len << std::endl;

    size_t alignment = volk_sha256_get_alignment();
    uint8_t* msg = (uint8_t*) volk_sha256_malloc(msg_len*sizeof(uint8_t), alignment);
    for(size_t k=0; k<msg_len; k++) msg[k] = (uint8_t) msg_char[k];

    uint32_t* hash = (uint32_t*) volk_sha256_malloc(8*sizeof(uint32_t), alignment);

    // Run generic kernel
    volk_sha256_8u_hash_32u_manual(hash, msg, msg_len, "generic");

    // Print hash from function
    std::cout << "Hash (hex, splitted): ";
    for(size_t k=0; k<8; k++) printf("%#08x ", hash[k]);
    std::cout << std::endl;
    std::cout << "Hash (hex, string): ";
    for(size_t k=0; k<8; k++) printf("%08x", hash[k]);
    std::cout << std::endl;

    // Set test on passed (0) or failed (1)
    return 0;
}
