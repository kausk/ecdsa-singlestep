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

unsigned long int Q = 999434999;
unsigned long int x_pk = 100030001;
unsigned long int PAGE_SIZE = 4096*5;
int unsigned_size = 32;
int outlen = 5;

__attribute__((aligned(4096))) unsigned long int a;

__attribute__((aligned(4096))) unsigned long int divrem_indicator;

__attribute__((aligned(4096))) unsigned long int add_indicator;

unsigned long int gcdExtended(unsigned long int a, unsigned long int b, unsigned long int *x, unsigned long int *y); 


unsigned long int addInts(unsigned long int x, unsigned long int y) {
    add_indicator++;
    return x + y;
}
unsigned long int divrem(unsigned long int v, unsigned long int modulus) {
    char seperator[PAGE_SIZE];
    divrem_indicator++;
    unsigned long int quotient = v / modulus;
    return v - (modulus * quotient);
}
void* get_DIVR_ADDR(void) {
    return (void*) divrem;
}

// Vulnerable function
unsigned long int mod(unsigned long int v, unsigned long int modulus) {
    char seperator[PAGE_SIZE];
    if (v < modulus) {
        return v;
    } else {
        unsigned long int remainder = divrem(v, modulus);
        return remainder; 
    }
}

unsigned long int random_int(unsigned long int start, unsigned long int end) {
    char seperator[PAGE_SIZE];
    unsigned long int val;
    sgx_read_rand((unsigned char *) &val, 4);
    return val % end;
}

unsigned long int mul(unsigned long int x, unsigned long int y) {
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

/* https://stackoverflow.com/questions/7666509/hash-function-for-string */
unsigned int hash(unsigned char *s)
{
  unsigned int hashval;

  for (hashval = 0; *s != '\0'; s++)
    hashval = *s + 31*hashval;
  return hashval % 65535;
}

/*
// djb2 from http://www.cse.yorku.ca/~oz/hash.html
unsigned long int hash(unsigned char *str) {
    char seperator[PAGE_SIZE];
    unsigned long hash = 5381;
    unsigned long int c;
    while (c = *str++)
        hash = ((hash << 5) + hash) + c; 
    return hash;
}
*/

/* Modular inverse from https://www.geeksforgeeks.org/multiplicative-inverse-under-modulo-m/ */
unsigned long int modular_inv(unsigned long int value, unsigned long int modulus) {
    char seperator[PAGE_SIZE];

    unsigned long int x, y;
    unsigned long int g = gcdExtended(a, modulus, &x, &y);
    if (g != 1) {
        return -1;
    } else { 
        return (x%modulus + modulus) % modulus; 
    }
}
unsigned long int gcdExtended(unsigned long int a, unsigned long int b, unsigned long int *x, unsigned long int *y) { 
    char seperator[PAGE_SIZE];

    if (a == 0) { 
        *x = 0, *y = 1; 
        return b; 
    } 
    unsigned long int x1, y1; // To store results of recursive call 
    unsigned long int gcd = gcdExtended(b%a, a, &x1, &y1); 
    *x = y1 - (b/a) * x1; 
    *y = x1; 
    return gcd; 
}

unsigned long int F(unsigned long int x, unsigned long int Q) {
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = (x >> 16) ^ x;
    return x % Q;
}

void* get_Add_ADDR(void) {
	return &add_indicator;
}
void* get_Mod_ADDR(void) {
	return &divrem_indicator;
}

 /* DUP */
unsigned long int ECDSA_sign(unsigned long int hashed_msg) {
    char seperator[PAGE_SIZE];
    /*
    unsigned long int hashed_msg = hash(msg);
    printf("hashed msg %d\n", hashed_msg >> (unsigned_size-outlen));
    */
    printf("message: %lu\n", hashed_msg);
    unsigned long int modded_msg = mod(hashed_msg, Q);
    unsigned long int k = random_int(1, Q);
    printf("Random int k %lu\n", k);
    unsigned long int k_inverse = modular_inv(k, Q);
    unsigned long int r = F(k, Q);
    printf("Hash fn r = F(k, Q) = %lu\n", r);
    unsigned long int rx = mul(r, x_pk);
    rx = mod(rx, Q);
    // start of side channel
    unsigned long int sum = addInts(modded_msg, rx);
    sum = mod(sum, Q);
    // if mod called div_rem, then we can establish ineq
    return r;
}
