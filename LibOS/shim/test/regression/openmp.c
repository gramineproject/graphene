/* build with: gcc -fopenmp openmp-test.c -o openmp-test */
#include <stdio.h>
#include <stdlib.h>
#include <omp.h>

int v[10];

int main(void) {
#pragma omp parallel for
    for (int i=0; i<10; i++)
        v[i] = i;

    printf("first: %d, last: %d\n", v[0], v[9]);
    return 0;
}
