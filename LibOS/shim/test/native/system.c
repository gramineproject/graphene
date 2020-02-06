#include <stdlib.h>

int main(int argc, char** argv) {
    if (system("./helloworld")) {
        return 1;
    }
    return 0;
}
