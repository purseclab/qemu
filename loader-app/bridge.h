typedef void * buffer_t;
typedef int array_t[10];
typedef struct struct_foo_t {
  uint32_t struct_foo_0;
  uint64_t struct_foo_1;
} struct_foo_t;
typedef union union_foo_t {
        uint32_t union_foo_0;
        uint32_t union_foo_1;
        uint64_t union_foo_3;
} union_foo_t;
typedef enum enum_foo_t {
        ENUM_FOO_0 = 0,
        ENUM_FOO_1 = 1,
} enum_foo_t;
size_t strlen (char * str);
sgx_status_t ecall_array_in_out (sgx_enclave_id_t eid, int arr[4]);
sgx_status_t ecall_array_in (sgx_enclave_id_t eid, int arr[4]);
sgx_status_t ecall_array_isary (sgx_enclave_id_t eid, array_t arr);
sgx_status_t ecall_array_out (sgx_enclave_id_t eid, int arr[4]);
sgx_status_t ecall_array_user_check (sgx_enclave_id_t eid, int arr[4]);
sgx_status_t ecall_consumer (sgx_enclave_id_t eid);
sgx_status_t ecall_exception (sgx_enclave_id_t eid);
sgx_status_t ecall_function_private (sgx_enclave_id_t eid, int * retval);
sgx_status_t ecall_function_public (sgx_enclave_id_t eid);
sgx_status_t ecall_increase_counter (sgx_enclave_id_t eid, size_t *  retval);
sgx_status_t ecall_malloc_free (sgx_enclave_id_t eid);
sgx_status_t ecall_map (sgx_enclave_id_t eid);
sgx_status_t ecall_pointer_count (sgx_enclave_id_t eid, int * arr, size_t cnt);
sgx_status_t ecall_pointer_in_out (sgx_enclave_id_t eid, int * val);
sgx_status_t ecall_pointer_in (sgx_enclave_id_t eid, int * val);
sgx_status_t ecall_pointer_isptr_readonly (sgx_enclave_id_t eid, buffer_t buf, size_t len);
sgx_status_t ecall_pointer_out (sgx_enclave_id_t eid, int * val);
sgx_status_t ecall_pointer_size (sgx_enclave_id_t eid, void * ptr, size_t len);
sgx_status_t ecall_pointer_string_const (sgx_enclave_id_t eid, const char * str);
sgx_status_t ecall_pointer_string (sgx_enclave_id_t eid, char * str);
sgx_status_t ecall_pointer_user_check (sgx_enclave_id_t eid, size_t *  retval, void * val, size_t sz);
sgx_status_t ecall_producer (sgx_enclave_id_t eid);
sgx_status_t ecall_sgx_cpuid (sgx_enclave_id_t eid, int cpuinfo[4], int leaf);
sgx_status_t ecall_type_char (sgx_enclave_id_t eid, char val);
sgx_status_t ecall_type_double (sgx_enclave_id_t eid, double val);
sgx_status_t ecall_type_enum_union (sgx_enclave_id_t eid, enum enum_foo_t val1, union union_foo_t *  val2);
sgx_status_t ecall_type_float (sgx_enclave_id_t eid, float val);
sgx_status_t ecall_type_int (sgx_enclave_id_t eid, int val);
sgx_status_t ecall_type_size_t (sgx_enclave_id_t eid, size_t val);
sgx_status_t ecall_type_struct (sgx_enclave_id_t eid, struct struct_foo_t val);
sgx_status_t ecall_type_wchar_t (sgx_enclave_id_t eid, wchar_t val);
sgx_status_t ocall_pointer_attr (sgx_enclave_id_t eid);
sgx_status_t testFuzzSGX (sgx_enclave_id_t eid);
