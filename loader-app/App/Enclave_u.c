#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_test_t {
	int ms_retval;
} ms_test_t;

typedef struct ms_test2_t {
	int ms_retval;
} ms_test2_t;

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Enclave = {
	0,
	{ NULL },
};
sgx_status_t test(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_test_t ms;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t test2(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_test2_t ms;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

