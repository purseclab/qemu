#include <assert.h>
#include <stdio.h>
#include <math.h>
#include <limits>
#define ULP 2
void ecall_array_in(int arr[4])
{
    for (int i = 0; i < 4; i++) {
        /* arr is not copied from App */
	printf("Array index:%d val:%d \n", i, arr[i]);
        assert(arr[i] == i);
	arr[i] = (3 - i);
	
    }
}
/* used to compare double variables in order to avoid compile warnings */
bool  almost_equal(float x, float y)
{
    /* the machine epsilon has to be scaled to the magnitude of the larger value
       and multiplied by the desired precision in ULPs (units in the last place) */
    return std::abs(x-y) <= std::numeric_limits<float>::epsilon() * std::abs(x+y) * ULP;
}

void ecall_type_float(float val)
{
    printf("%d \n", val);
    assert(almost_equal(val, (float)1234.0));
    printf("%d \n", val);
}
int main() {
	int arr[4] = {0,1,2,3};
	ecall_array_in(arr);
	ecall_type_float(124.0);
}
