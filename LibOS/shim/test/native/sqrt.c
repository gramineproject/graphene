#include <math.h>
#include <stdio.h>

int main(int argc, char** argv) {
    float x;

    printf("enter a float: ");
    fflush(stdin);
    if (scanf("%f", &x) != 1) {
        perror("reading error");
        return 1;
    }
    printf("sqrt(x) = %f\n", sqrt(x));

    return 0;
}
