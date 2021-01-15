#include <stdlib.h>

int main(int argc, char** argv) {
    if (system("./helloworld_pthread")) {
        return 1;
    }
    return 0;
}
