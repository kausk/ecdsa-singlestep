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


#include <stdio.h>      /* vsnprintf */
#include <stdarg.h>
#include "tSgxSSL_api.h"
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

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

void* get_ECDSA_sign_ADDR(void) {
	return (void*) ECDSA_do_sign_ex;
}
void* get_BN_mod_aq_ADDR(void) {
	return (void*) BN_mod_add_quick;
}
void* get_BN_usub_ADDR(void) {
	return (void*) BN_usub;
}
void* get_ECDSA_free_ADDR(void) {
	return (void*) ECDSA_SIG_free;
}

BIGNUM sign_single(unsigned char* message, int len) {	
	EC_KEY *key = NULL;
	BIGNUM *kinv = NULL, *rp = NULL;
	int nid = OBJ_txt2nid("secp384r1");
	ECDSA_SIG *signature = NULL;
	const BIGNUM *sig_r, *sig_s;

    BIGNUM* copy;
    copy = (BIGNUM *) malloc(sizeof(BIGNUM));	
	
	key = EC_KEY_new_by_curve_name(nid);
	EC_KEY_generate_key(key);
	ECDSA_sign_setup(key, NULL, &kinv, &rp);

	unsigned char buffer[len];
	int i;
	for (i = 0; i < len; i++) {
		buffer[i] = message[i];
	}

	signature = ECDSA_do_sign_ex(buffer, len, kinv, rp, key);
	ECDSA_SIG_get0(signature, &sig_r, &sig_s);
	/*
	EC_KEY_free(key);
	*/
	
	BN_copy(copy, sig_r);
	return *copy;
}
