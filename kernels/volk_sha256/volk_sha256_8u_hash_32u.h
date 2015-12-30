/* -*- c++ -*- */
/*
 * Copyright 2015 Stefan Wunsch
 *
 * This file is part of GNU Radio
 *
 * GNU Radio is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 *
 * GNU Radio is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Radio; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */

#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <volk_sha256/volk_sha256.h>

/*
 * NOTE:
 * We suppose a little endian machine.
 * Reference: https://web.archive.org/web/20150315061807/http://csrc.nist.gov/groups/STM/cavp/documents/shs/sha256-384-512.pdf
 */

#ifndef INCLUDED_volk_sha256_8u_hash_32u_a_H
#define INCLUDED_volk_sha256_8u_hash_32u_a_H

/* Define operations needed for sha256 main loop */
#define ROTL(x, n)      ( (x << n) | (x >> (sizeof(x)*8 - n)) )
#define ROTR(x, n)      ( (x >> n) | (x << (sizeof(x)*8 - n)) )
#define CH(x, y, z)     ( (x & y) ^ ((~x) & z) )
#define MAJ(x, y, z)    ( (x & y) ^ (x & z) ^ (y & z) )
#define EPSILON_0(x)    ( ROTR(x, 2)  ^  ROTR(x, 13)  ^  ROTR(x, 22) )
#define EPSILON_1(x)    ( ROTR(x, 6)  ^  ROTR(x, 11)  ^  ROTR(x, 25) )
#define SIGMA_0(x)      ( ROTR(x, 7)  ^  ROTR(x, 18)  ^  (x >> 3) )
#define SIGMA_1(x)      ( ROTR(x, 17) ^  ROTR(x, 19)  ^  (x >> 10) )

/* Process one block of 512 bits in the sha256 main loop */
static inline void
sha256_process_block(uint32_t* hash, uint32_t* msg){
    uint32_t a, b, c, d, e, f, g, h, T1, T2, W[64];
    unsigned int i;

    static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

    // Calculate W
    for (i = 0; i < 16; i++) W[i] = msg[i];
    for (i = 16; i < 64; i++) W[i] = SIGMA_1(W[i-2]) + W[i-7] + SIGMA_0(W[i-15]) + W[i-16];

    // Init a to h
    a = hash[0];
    b = hash[1];
    c = hash[2];
    d = hash[3];
    e = hash[4];
    f = hash[5];
    g = hash[6];
    h = hash[7];

    // Run sha256 compression function
    for(i=0; i<64; i++){
        T1 = h + EPSILON_1(e) + CH(e, f, g) + K[i] + W[i];
        T2 = EPSILON_0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
		a = T1 + T2;
    }

    // Get intermidiate hash
    hash[0] = a + hash[0];
    hash[1] = b + hash[1];
    hash[2] = c + hash[2];
    hash[3] = d + hash[3];
    hash[4] = e + hash[4];
    hash[5] = f + hash[5];
    hash[6] = g + hash[6];
    hash[7] = h + hash[7];
}

#ifdef LV_HAVE_GENERIC

static inline void
volk_sha256_8u_hash_32u_generic(uint32_t* hash, const uint8_t* msg, unsigned int msg_len)
{
    /* INIT*/

    // Set initial hash
    hash[0] = 0x6a09e667;
    hash[1] = 0xbb67ae85;
    hash[2] = 0x3c6ef372;
    hash[3] = 0xa54ff53a;
    hash[4] = 0x510e527f;
    hash[5] = 0x9b05688c;
    hash[6] = 0x1f83d9ab;
    hash[7] = 0x5be0cd19;

    /* MAIN LOOP: Process blocks of 512 bits without padding */

    const unsigned int N = msg_len / 64; // number of full 512 bit blocks
    unsigned int i;
    uint32_t* msg_block; // pointer to 512 bit blocks of input message
    for(i=0; i<N; i++){
        printf("LOOP\n"); // FIXME
        msg_block = (uint32_t*) (msg + 64*i); // increment pointer to next multiple of 512 bits
        sha256_process_block(hash, msg_block); // process one main loop step
    }

    /* PADDING: Process rest of bits (msg_len%64 bytes) after processing of all 512 bits blocks */

    const unsigned int R = msg_len % 64; // rest bytes from input message
    size_t alignment = volk_sha256_get_alignment(); // get system alignment
    msg_block = (uint32_t*) volk_sha256_malloc(4*16, alignment); // allocate 512 bits
    uint8_t* msg_block_b = (uint8_t*) msg_block; // byte-wise pointer

    memcpy(msg_block_b, msg+N*64, R); // copy rest of message to intermediate buffer
    msg_block_b[R] = 0x80; // add 0x80 (1 bit followed by zeros) to message

    if(R<56){ // if at least 8 bytes are free up to 512 bits, then set last 64 bit here
        for(i=R+1; i<56; i++) msg_block_b[R] = 0x00; // set rest up to last 8 byte to zero
    }
    else{ // otherwise start a new block
        for(i=R+1; i<64; i++) msg_block_b[R] = 0x00; // set rest to zero
        sha256_process_block(hash, msg_block); // update hash
        for(i=0; i<56; i++) msg_block_b[R] = 0x00; // set rest up to last 8 byte to zero
    }

    // write last 8 bytes with message length in bits in big endian format
    const uint64_t msg_len_bits = msg_len*8;
    for (i = 0; i < 8; i++) msg_block_b[63 - i] = msg_len_bits >> (i*8);

    // update hash the last time
    sha256_process_block(hash, msg_block);

    volk_sha256_free(msg_block);
}
#endif /* LV_HAVE_GENERIC */

#endif /* INCLUDED_volk_sha256_8u_hash_32u_a_H */
