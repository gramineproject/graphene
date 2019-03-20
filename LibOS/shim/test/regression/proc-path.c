#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main (int argc, const char ** argv)
{
    DIR * d, * root;
    struct dirent * dir, * root_dir;

    d = opendir("/proc/1/root");
    if (!d) {
        perror("opendir /proc/1/root");
        exit(1);
    }

    root = opendir("/");
    if (!root) {
        perror("opendir /");
        exit(1);
    }

    do {
        if ((root_dir = readdir(root)) == NULL) {
            if ((readdir(d)) == NULL) {
                printf("proc path test success\n");
	        goto out;
	    } else {
                break;
	    }
	}

        if ((dir = readdir(d)) == NULL) {
                printf("proc path test failure\n");
                goto out;
        }
    } while (!strcmp(dir->d_name, root_dir->d_name));

    printf("proc path test failure\n");

out:
    closedir(d);
    closedir(root);

    return(0);
}
