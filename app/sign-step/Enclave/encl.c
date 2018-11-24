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
#include <stdarg.h>

int Q = 93529;
int x_pk = 46261;
int PAGE_SIZE = 4096*5;

__attribute__((aligned(4096))) int a;

__attribute__((aligned(4096))) int mod_indicator;

__attribute__((aligned(4096))) int add_indicator;

unsigned long gcdExtended(unsigned long a, unsigned long b, unsigned long *x, unsigned long *y); 


unsigned long addInts(unsigned long x, unsigned long y) {
    add_indicator++;
    return x + y;
}
unsigned long divrem(unsigned long v, unsigned long modulus) {
    char seperator[PAGE_SIZE];
    unsigned long quotient = v / modulus;
    return v - (modulus * quotient);
}
void* get_DIVR_ADDR(void) {
    return (void*) divrem;
}

// Vulnerable function
unsigned long mod(unsigned long v, unsigned long modulus) {
    char seperator[PAGE_SIZE];
    mod_indicator++;
    if (v < modulus) {
        return v;
    } else {
        unsigned long remainder = divrem(v, modulus);
        return remainder; 
    }
}

unsigned long random_int(unsigned long start, unsigned long end) {
    char seperator[PAGE_SIZE];
    unsigned long val;
    sgx_read_rand((unsigned char *) &val, 4);
    return val % end;
}

unsigned long mul(unsigned long x, unsigned long y) {
    return x * y;
}

void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    uprint(buf);
}


void* get_a_addr( void )
{
    return &a;
}

void enclave_dummy_call(void)
{
    a++;
    return;
}

// djb2 from http://www.cse.yorku.ca/~oz/hash.html
unsigned long hash(unsigned char *str) {
    unsigned long hash = 5381;
    int c;
    while (c = *str++)
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    printf("computed hash %d\n", hash);
    return hash;
}

/* Modular inverse from https://www.geeksforgeeks.org/multiplicative-inverse-under-modulo-m/ */
unsigned long modular_inv(unsigned long value, unsigned long modulus) {
    char seperator[PAGE_SIZE];

    unsigned long x, y;
    unsigned long g = gcdExtended(a, modulus, &x, &y);
    if (g != 1) {
        return -1;
    } else { 
        return (x%modulus + modulus) % modulus; 
    }
}
unsigned long gcdExtended(unsigned long a, unsigned long b, unsigned long *x, unsigned long *y) { 
    char seperator[PAGE_SIZE];

    if (a == 0) { 
        *x = 0, *y = 1; 
        return b; 
    } 
    unsigned long x1, y1; // To store results of recursive call 
    unsigned long gcd = gcdExtended(b%a, a, &x1, &y1); 
    *x = y1 - (b/a) * x1; 
    *y = x1; 
    return gcd; 
}

unsigned long F(int v, int Q) {
    unsigned char str[21];
    snprintf(str, 10, "%d", v);
    printf("integer %s\n", str);
    return hash(&str) % Q;
}

void* get_Add_ADDR(void) {
	return &add_indicator;
}
void* get_Mod_ADDR(void) {
	return &mod_indicator;
}


 /* DUP */


unsigned long ECDSA_sign(char* msg) {
    unsigned char seperator[PAGE_SIZE];

    unsigned long hashed_msg = hash(msg) % Q;
    unsigned long modded_msg = mod(hashed_msg, Q);
    unsigned long k = random_int(1, Q);
    unsigned long k_inverse = modular_inv(k, Q);
    unsigned long r = F(k, Q);
    unsigned long rx = mul(r, x_pk);
    rx = mod(rx, Q);
    // start of side channel
    unsigned long sum = addInts(modded_msg, rx);
    sum = mod(sum, Q);
    unsigned long s = mul(k_inverse, sum);
    s = mod(s, Q);
    printf("Signed value %d\n",  s);
    return r;
}