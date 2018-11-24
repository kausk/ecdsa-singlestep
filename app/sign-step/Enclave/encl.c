/*
 *  This file is part of the SGX-Step enclave execution control framework.
 *
 *  Copyright (C) 2017 Jo Van Bulck <jo.vanbulck@cs.kuleuven.be>,
 *                     Raoul Strackx <raoul.strackx@cs.kuleuven.be>
 *
 *  SGX-Step is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  SGX-Step is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with SGX-Step. If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdint.h>
#include <sgx_trts.h>
#include <stdio.h>
#include <stdlib.h>

int Q = 93529;
int x_pk = 46261;

__attribute__((aligned(4096))) int a;

void* get_a_addr( void )
{
    return &a;
}

void enclave_dummy_call(void)
{
    a++;
    return;
}

int ECDSA_sign(char* msg) {
    int hashed_msg = hash(msg) % Q;
    int modded_msg = mod(hashed_msg, Q);
    int k = random_int(1, Q);
    int k_inverse = modular_inv(k, Q);
    int r = F(k);
    int rx = mul(r, x_pk);
    rx = mod(rx, Q);
    // start of side channel
    int sum = add(modded_msg, rx);
    sum = mod(sum, Q);
    int s = mul(k_inverse, sum);
    s = mod(s, Q);
    return r;
}

// djb2 from http://www.cse.yorku.ca/~oz/hash.html
int hash(unsigned char *str) {
    int hash = 5381;
    int c;
    while (c = *str++)
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    return hash;
}

int random_int(int start, int end) {
    uint32_t val;
    sgx_read_rand((unsigned char *) &val, 4);
    return val % end;
}

/* Modular inverse from https://www.geeksforgeeks.org/multiplicative-inverse-under-modulo-m/ */
int modular_inv(int value, int modulus) {
    int x, y;
    int g = gcdExtended(a, modulus, &x, &y);
    if (g != 1) {
        return -1;
    } else { 
        return (x%modulus + modulus) % modulus; 
    }
}
int gcdExtended(int a, int b, int *x, int *y) { 
    if (a == 0) { 
        *x = 0, *y = 1; 
        return b; 
    } 
    int x1, y1; // To store results of recursive call 
    int gcd = gcdExtended(b%a, a, &x1, &y1); 
    *x = y1 - (b/a) * x1; 
    *y = x1; 
    return gcd; 
}

int F(int v, int Q) {
    char str[21];
    //itoa(v, str, 10);
    snprintf(str, 10, "%d", v);
    return hash(&str) % Q;
}

int mul(int x, int y) {
    return x * y;
}

// Vulnerable function
int mod(int v, int modulus) {
    if (v < modulus) {
        return v;
    } else {
        int remainder = divrem(v, modulus);
        return remainder; 
    }
}

int divrem(int v, int modulus) {
    printf("div rem being called");
    int quotient = v / modulus;
    return v - (modulus * quotient);
}

int add(int x, int y) {
    return x + y;
}
