#include <stdio.h>
#include <dirent.h>

static int showdir(char* dir) {
    struct dirent* de;

    DIR *dr = opendir(dir);
    if (!dr) {
        printf("Could not open directory `%s`\n", dir);
        return 1;
    }

    printf("Contents of directory `%s`:\n", dir);
    while ((de = readdir(dr)))
        printf("  %s\n", de->d_name);
    printf("\n");

    closedir(dr);
    return 0;
}

int main(int argc, char** argv) {
    if (showdir("/"))
        return 1;

    if (showdir("/var/"))
        return 1;

    puts("Test was successful");
    return 0;
}
