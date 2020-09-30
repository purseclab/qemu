#include <assert.h>
#include <stdio.h>
void ecall_array_in(int arr[4])
{
    for (int i = 0; i < 4; i++) {
        /* arr is not copied from App */
	printf("Array index:%d val:%d \n", i, arr[i]);
        assert(arr[i] == i);
	arr[i] = (3 - i);
	
    }
}
int main() {
	int arr[4] = {0,1,2,3};
	ecall_array_in(arr);
}
