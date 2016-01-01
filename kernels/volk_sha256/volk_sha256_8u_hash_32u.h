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
 * Check against sha256sum on a linux system. Be aware of the file ending character inserted by many text editors (sth like CR).
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
#define SWAP_UINT32(x)  ( ((x) >> 24) | (((x) & 0x00FF0000) >> 8) | (((x) & 0x0000FF00) << 8) | ((x) << 24) )

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

/* GENERIC: Single round in the sha256 main loop */
#define	SHA256_ROUND_GENERIC(a, b, c, d, e, f, g, h, W, K) \
T1 = h + EPSILON_1(e) + CH(e, f, g) + W + K;               \
d += T1;                                                   \
T2 = EPSILON_0(a) + MAJ(a, b, c);                          \
h = T1 + T2

/* GENERIC: Process one block of 512 bits in the sha256 main loop */
static inline void
sha256_process_block_generic(uint32_t* hash, const uint32_t* msg){
    uint32_t W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14, W15;
    uint32_t T1, T2;
    uint32_t a, b, c, d, e, f, g, h;

    // Run sha256 compression function with included computation of W

    // Init a to h with given hash
    a = hash[0];
    b = hash[1];
    c = hash[2];
    d = hash[3];
    e = hash[4];
    f = hash[5];
    g = hash[6];
    h = hash[7];

    // Omit the loop implementation to increase performance
    // Loop form:
    /*

    // Calculate W
    for (i = 0; i < 16; i++){
        W[i] = SWAP_UINT32(msg[i]);
    }
    for (i = 16; i < 64; i++) W[i] = SIGMA_1(W[i-2]) + W[i-7] + SIGMA_0(W[i-15]) + W[i-16];

    // Sha256 compression function
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
    */

    // Implement rounds explicitly
    // Start with first 16 rounds from 0 to 15
    W0 = SWAP_UINT32(msg[0]);
    SHA256_ROUND_GENERIC(a, b, c, d, e, f, g, h, W0, K[0]);
    W1 = SWAP_UINT32(msg[1]);
    SHA256_ROUND_GENERIC(h, a, b, c, d, e, f, g, W1, K[1]);
    W2 = SWAP_UINT32(msg[2]);
    SHA256_ROUND_GENERIC(g, h, a, b, c, d, e, f, W2, K[2]);
    W3 = SWAP_UINT32(msg[3]);
    SHA256_ROUND_GENERIC(f, g, h, a, b, c, d, e, W3, K[3]);
    W4 = SWAP_UINT32(msg[4]);
    SHA256_ROUND_GENERIC(e, f, g, h, a, b, c, d, W4, K[4]);
    W5 = SWAP_UINT32(msg[5]);
    SHA256_ROUND_GENERIC(d, e, f, g, h, a, b, c, W5, K[5]);
    W6 = SWAP_UINT32(msg[6]);
    SHA256_ROUND_GENERIC(c, d, e, f, g, h, a, b, W6, K[6]);
    W7 = SWAP_UINT32(msg[7]);
    SHA256_ROUND_GENERIC(b, c, d, e, f, g, h, a, W7, K[7]);
    W8 = SWAP_UINT32(msg[8]);
    SHA256_ROUND_GENERIC(a, b, c, d, e, f, g, h, W8, K[8]);
    W9 = SWAP_UINT32(msg[9]);
    SHA256_ROUND_GENERIC(h, a, b, c, d, e, f, g, W9, K[9]);
    W10 = SWAP_UINT32(msg[10]);
    SHA256_ROUND_GENERIC(g, h, a, b, c, d, e, f, W10, K[10]);
    W11 = SWAP_UINT32(msg[11]);
    SHA256_ROUND_GENERIC(f, g, h, a, b, c, d, e, W11, K[11]);
    W12 = SWAP_UINT32(msg[12]);
    SHA256_ROUND_GENERIC(e, f, g, h, a, b, c, d, W12, K[12]);
    W13 = SWAP_UINT32(msg[13]);
    SHA256_ROUND_GENERIC(d, e, f, g, h, a, b, c, W13, K[13]);
    W14 = SWAP_UINT32(msg[14]);
    SHA256_ROUND_GENERIC(c, d, e, f, g, h, a, b, W14, K[14]);
    W15 = SWAP_UINT32(msg[15]);
    SHA256_ROUND_GENERIC(b, c, d, e, f, g, h, a, W15, K[15]);

    // Second 16 rounds from 16 to 31
    W0 = SIGMA_1(W14) + W9 + SIGMA_0(W1) + W0;
    SHA256_ROUND_GENERIC(a, b, c, d, e, f, g, h, W0, K[16]);
    W1 = SIGMA_1(W15) + W10 + SIGMA_0(W2) + W1;
    SHA256_ROUND_GENERIC(h, a, b, c, d, e, f, g, W1, K[17]);
    W2 = SIGMA_1(W0) + W11 + SIGMA_0(W3) + W2;
    SHA256_ROUND_GENERIC(g, h, a, b, c, d, e, f, W2, K[18]);
    W3 = SIGMA_1(W1) + W12 + SIGMA_0(W4) + W3;
    SHA256_ROUND_GENERIC(f, g, h, a, b, c, d, e, W3, K[19]);
    W4 = SIGMA_1(W2) + W13 + SIGMA_0(W5) + W4;
    SHA256_ROUND_GENERIC(e, f, g, h, a, b, c, d, W4, K[20]);
    W5 = SIGMA_1(W3) + W14 + SIGMA_0(W6) + W5;
    SHA256_ROUND_GENERIC(d, e, f, g, h, a, b, c, W5, K[21]);
    W6 = SIGMA_1(W4) + W15 + SIGMA_0(W7) + W6;
    SHA256_ROUND_GENERIC(c, d, e, f, g, h, a, b, W6, K[22]);
    W7 = SIGMA_1(W5) + W0 + SIGMA_0(W8) + W7;
    SHA256_ROUND_GENERIC(b, c, d, e, f, g, h, a, W7, K[23]);
    W8 = SIGMA_1(W6) + W1 + SIGMA_0(W9) + W8;
    SHA256_ROUND_GENERIC(a, b, c, d, e, f, g, h, W8, K[24]);
    W9 = SIGMA_1(W7) + W2 + SIGMA_0(W10) + W9;
    SHA256_ROUND_GENERIC(h, a, b, c, d, e, f, g, W9, K[25]);
    W10 = SIGMA_1(W8) + W3 + SIGMA_0(W11) + W10;
    SHA256_ROUND_GENERIC(g, h, a, b, c, d, e, f, W10, K[26]);
    W11 = SIGMA_1(W9) + W4 + SIGMA_0(W12) + W11;
    SHA256_ROUND_GENERIC(f, g, h, a, b, c, d, e, W11, K[27]);
    W12 = SIGMA_1(W10) + W5 + SIGMA_0(W13) + W12;
    SHA256_ROUND_GENERIC(e, f, g, h, a, b, c, d, W12, K[28]);
    W13 = SIGMA_1(W11) + W6 + SIGMA_0(W14) + W13;
    SHA256_ROUND_GENERIC(d, e, f, g, h, a, b, c, W13, K[29]);
    W14 = SIGMA_1(W12) + W7 + SIGMA_0(W15) + W14;
    SHA256_ROUND_GENERIC(c, d, e, f, g, h, a, b, W14, K[30]);
    W15 = SIGMA_1(W13) + W8 + SIGMA_0(W0) + W15;
    SHA256_ROUND_GENERIC(b, c, d, e, f, g, h, a, W15, K[31]);

    // Third 16 rounds from 32 to 47
    W0 = SIGMA_1(W14) + W9 + SIGMA_0(W1) + W0;
    SHA256_ROUND_GENERIC(a, b, c, d, e, f, g, h, W0, K[32]);
    W1 = SIGMA_1(W15) + W10 + SIGMA_0(W2) + W1;
    SHA256_ROUND_GENERIC(h, a, b, c, d, e, f, g, W1, K[33]);
    W2 = SIGMA_1(W0) + W11 + SIGMA_0(W3) + W2;
    SHA256_ROUND_GENERIC(g, h, a, b, c, d, e, f, W2, K[34]);
    W3 = SIGMA_1(W1) + W12 + SIGMA_0(W4) + W3;
    SHA256_ROUND_GENERIC(f, g, h, a, b, c, d, e, W3, K[35]);
    W4 = SIGMA_1(W2) + W13 + SIGMA_0(W5) + W4;
    SHA256_ROUND_GENERIC(e, f, g, h, a, b, c, d, W4, K[36]);
    W5 = SIGMA_1(W3) + W14 + SIGMA_0(W6) + W5;
    SHA256_ROUND_GENERIC(d, e, f, g, h, a, b, c, W5, K[37]);
    W6 = SIGMA_1(W4) + W15 + SIGMA_0(W7) + W6;
    SHA256_ROUND_GENERIC(c, d, e, f, g, h, a, b, W6, K[38]);
    W7 = SIGMA_1(W5) + W0 + SIGMA_0(W8) + W7;
    SHA256_ROUND_GENERIC(b, c, d, e, f, g, h, a, W7, K[39]);
    W8 = SIGMA_1(W6) + W1 + SIGMA_0(W9) + W8;
    SHA256_ROUND_GENERIC(a, b, c, d, e, f, g, h, W8, K[40]);
    W9 = SIGMA_1(W7) + W2 + SIGMA_0(W10) + W9;
    SHA256_ROUND_GENERIC(h, a, b, c, d, e, f, g, W9, K[41]);
    W10 = SIGMA_1(W8) + W3 + SIGMA_0(W11) + W10;
    SHA256_ROUND_GENERIC(g, h, a, b, c, d, e, f, W10, K[42]);
    W11 = SIGMA_1(W9) + W4 + SIGMA_0(W12) + W11;
    SHA256_ROUND_GENERIC(f, g, h, a, b, c, d, e, W11, K[43]);
    W12 = SIGMA_1(W10) + W5 + SIGMA_0(W13) + W12;
    SHA256_ROUND_GENERIC(e, f, g, h, a, b, c, d, W12, K[44]);
    W13 = SIGMA_1(W11) + W6 + SIGMA_0(W14) + W13;
    SHA256_ROUND_GENERIC(d, e, f, g, h, a, b, c, W13, K[45]);
    W14 = SIGMA_1(W12) + W7 + SIGMA_0(W15) + W14;
    SHA256_ROUND_GENERIC(c, d, e, f, g, h, a, b, W14, K[46]);
    W15 = SIGMA_1(W13) + W8 + SIGMA_0(W0) + W15;
    SHA256_ROUND_GENERIC(b, c, d, e, f, g, h, a, W15, K[47]);

    // Fourth 16 rounds from 48 to 63
    W0 = SIGMA_1(W14) + W9 + SIGMA_0(W1) + W0;
    SHA256_ROUND_GENERIC(a, b, c, d, e, f, g, h, W0, K[48]);
    W1 = SIGMA_1(W15) + W10 + SIGMA_0(W2) + W1;
    SHA256_ROUND_GENERIC(h, a, b, c, d, e, f, g, W1, K[49]);
    W2 = SIGMA_1(W0) + W11 + SIGMA_0(W3) + W2;
    SHA256_ROUND_GENERIC(g, h, a, b, c, d, e, f, W2, K[50]);
    W3 = SIGMA_1(W1) + W12 + SIGMA_0(W4) + W3;
    SHA256_ROUND_GENERIC(f, g, h, a, b, c, d, e, W3, K[51]);
    W4 = SIGMA_1(W2) + W13 + SIGMA_0(W5) + W4;
    SHA256_ROUND_GENERIC(e, f, g, h, a, b, c, d, W4, K[52]);
    W5 = SIGMA_1(W3) + W14 + SIGMA_0(W6) + W5;
    SHA256_ROUND_GENERIC(d, e, f, g, h, a, b, c, W5, K[53]);
    W6 = SIGMA_1(W4) + W15 + SIGMA_0(W7) + W6;
    SHA256_ROUND_GENERIC(c, d, e, f, g, h, a, b, W6, K[54]);
    W7 = SIGMA_1(W5) + W0 + SIGMA_0(W8) + W7;
    SHA256_ROUND_GENERIC(b, c, d, e, f, g, h, a, W7, K[55]);
    W8 = SIGMA_1(W6) + W1 + SIGMA_0(W9) + W8;
    SHA256_ROUND_GENERIC(a, b, c, d, e, f, g, h, W8, K[56]);
    W9 = SIGMA_1(W7) + W2 + SIGMA_0(W10) + W9;
    SHA256_ROUND_GENERIC(h, a, b, c, d, e, f, g, W9, K[57]);
    W10 = SIGMA_1(W8) + W3 + SIGMA_0(W11) + W10;
    SHA256_ROUND_GENERIC(g, h, a, b, c, d, e, f, W10, K[58]);
    W11 = SIGMA_1(W9) + W4 + SIGMA_0(W12) + W11;
    SHA256_ROUND_GENERIC(f, g, h, a, b, c, d, e, W11, K[59]);
    W12 = SIGMA_1(W10) + W5 + SIGMA_0(W13) + W12;
    SHA256_ROUND_GENERIC(e, f, g, h, a, b, c, d, W12, K[60]);
    W13 = SIGMA_1(W11) + W6 + SIGMA_0(W14) + W13;
    SHA256_ROUND_GENERIC(d, e, f, g, h, a, b, c, W13, K[61]);
    W14 = SIGMA_1(W12) + W7 + SIGMA_0(W15) + W14;
    SHA256_ROUND_GENERIC(c, d, e, f, g, h, a, b, W14, K[62]);
    W15 = SIGMA_1(W13) + W8 + SIGMA_0(W0) + W15;
    SHA256_ROUND_GENERIC(b, c, d, e, f, g, h, a, W15, K[63]);

    // Get intermediate hash
    hash[0] += a;
    hash[1] += b;
    hash[2] += c;
    hash[3] += d;
    hash[4] += e;
    hash[5] += f;
    hash[6] += g;
    hash[7] += h;
}

#ifdef LV_HAVE_GENERIC

static inline void
volk_sha256_8u_hash_32u_generic(uint32_t* hash, const uint8_t* msg, unsigned int msg_len)
{
    /* INIT: Set initial hash */

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
        msg_block = (uint32_t*) (msg + 64*i); // increment pointer to next multiple of 512 bits
        sha256_process_block_generic(hash, msg_block); // process one main loop step
    }

    /* PADDING AND LAST HASH UPDATE: Process rest of bits (msg_len%64 bytes) after processing of all 512 bits blocks */

    const unsigned int R = msg_len % 64; // rest bytes from input message
    size_t alignment = volk_sha256_get_alignment(); // get system alignment
    msg_block = (uint32_t*) volk_sha256_malloc(4*16, alignment); // allocate 512 bits
    uint8_t* msg_block_b = (uint8_t*) msg_block; // byte-wise pointer

    memcpy(msg_block_b, msg+N*64, R); // copy rest of message to intermediate buffer
    msg_block_b[R] = 0x80; // add 0x80 (1 followed by zeros) to message

    if(R<56){ // if at least 8 bytes are free up to 512 bits, then set last 64 bit here
        for(i=R+1; i<56; i++) msg_block_b[i] = 0x00; // set rest up to last 8 byte to zero
    }
    else{ // otherwise start a new block
        for(i=R+1; i<64; i++) msg_block_b[i] = 0x00; // set rest to zero
        sha256_process_block_generic(hash, msg_block); // update hash
        for(i=0; i<56; i++) msg_block_b[i] = 0x00; // set rest up to last 8 byte to zero
    }

    // write last 8 bytes with message length in bits in big endian format
    const uint64_t msg_len_bits = msg_len*8;
    for (i = 0; i < 8; i++) msg_block_b[63 - i] = msg_len_bits >> (i*8);

    // update hash the last time
    sha256_process_block_generic(hash, msg_block);

    volk_sha256_free(msg_block);
}

#endif /* LV_HAVE_GENERIC */

/* SSE: Process one block of 512 bits in the sha256 main loop */
static inline void
sha256_process_block_sse(uint32_t* hash, const uint32_t* msg){
    uint32_t a, b, c, d, e, f, g, h, T1, T2, W[64];
    unsigned int i;

    // Calculate W
    for (i = 0; i < 16; i++){
        W[i] = SWAP_UINT32(msg[i]);
    }
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
    // NOTE: here goes the SSE magic! All other code is untouched compared to the generic version.
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

    // Get intermediate hash
    hash[0] = a + hash[0];
    hash[1] = b + hash[1];
    hash[2] = c + hash[2];
    hash[3] = d + hash[3];
    hash[4] = e + hash[4];
    hash[5] = f + hash[5];
    hash[6] = g + hash[6];
    hash[7] = h + hash[7];
}

#ifdef LV_HAVE_SSE

static inline void
volk_sha256_8u_hash_32u_a_sse(uint32_t* hash, const uint8_t* msg, unsigned int msg_len)
{
    /* INIT: Set initial hash */

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
        msg_block = (uint32_t*) (msg + 64*i); // increment pointer to next multiple of 512 bits
        sha256_process_block_sse(hash, msg_block); // process one main loop step
    }

    /* PADDING AND LAST HASH UPDATE: Process rest of bits (msg_len%64 bytes) after processing of all 512 bits blocks */

    const unsigned int R = msg_len % 64; // rest bytes from input message
    size_t alignment = volk_sha256_get_alignment(); // get system alignment
    msg_block = (uint32_t*) volk_sha256_malloc(4*16, alignment); // allocate 512 bits
    uint8_t* msg_block_b = (uint8_t*) msg_block; // byte-wise pointer

    memcpy(msg_block_b, msg+N*64, R); // copy rest of message to intermediate buffer
    msg_block_b[R] = 0x80; // add 0x80 (1 followed by zeros) to message

    if(R<56){ // if at least 8 bytes are free up to 512 bits, then set last 64 bit here
        for(i=R+1; i<56; i++) msg_block_b[i] = 0x00; // set rest up to last 8 byte to zero
    }
    else{ // otherwise start a new block
        for(i=R+1; i<64; i++) msg_block_b[i] = 0x00; // set rest to zero
        sha256_process_block_sse(hash, msg_block); // update hash
        for(i=0; i<56; i++) msg_block_b[i] = 0x00; // set rest up to last 8 byte to zero
    }

    // write last 8 bytes with message length in bits in big endian format
    const uint64_t msg_len_bits = msg_len*8;
    for (i = 0; i < 8; i++) msg_block_b[63 - i] = msg_len_bits >> (i*8);

    // update hash the last time
    sha256_process_block_sse(hash, msg_block);

    volk_sha256_free(msg_block);
}

#endif /* LV_HAVE_SSE */

#endif /* INCLUDED_volk_sha256_8u_hash_32u_a_H */
