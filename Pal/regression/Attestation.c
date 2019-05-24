#include "pal.h"
#include "pal_debug.h"

int main(int argc, char** argv, char** envp) {
    pal_printf("Attestation status: %s\n",      pal_control.attestation_status);
    pal_printf("Attestation timestamp: %s\n",   pal_control.attestation_timestamp);
    return 0;
}
