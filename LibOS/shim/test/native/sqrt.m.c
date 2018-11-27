#include <stdio.h>
#include <math.h>

int main(int argc, char ** argv) {
    float x;

    printf("enter a float: ");
    fflush(stdin);
    scanf("%f", &x);
    printf("sqrt(x) = %f\n", sqrt(x));

    return 0;
}
