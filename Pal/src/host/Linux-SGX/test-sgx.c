#include <stdio.h>

static inline void native_cpuid(unsigned int* eax, unsigned int* ebx, unsigned int* ecx,
                                unsigned int* edx) {
    /* ecx is often an input as well as an output. */
    asm volatile("cpuid" : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx) : "0"(*eax), "2"(*ecx));
}

int main(int argc, char** argv) {
    /* This programm prints some CPUID information and tests the SGX support of the CPU */

    unsigned eax, ebx, ecx, edx;
    eax = 1; /* processor info and feature bits */

    native_cpuid(&eax, &ebx, &ecx, &edx);
    printf("eax: %x ebx: %x ecx: %x edx: %x\n", eax, ebx, ecx, edx);

    printf("stepping %d\n", eax & 0xF);                  // Bit 3-0
    printf("model %d\n", (eax >> 4) & 0xF);              // Bit 7-4
    printf("family %d\n", (eax >> 8) & 0xF);             // Bit 11-8
    printf("processor type %d\n", (eax >> 12) & 0x3);    // Bit 13-12
    printf("extended model %d\n", (eax >> 16) & 0xF);    // Bit 19-16
    printf("extended family %d\n", (eax >> 20) & 0xFF);  // Bit 27-20

    // if smx set - SGX global enable is supported
    printf("smx: %d\n", (ecx >> 6) & 1);  // CPUID.1:ECX.[bit6]

    /* Extended feature bits (EAX=07H, ECX=0H)*/
    printf("\nExtended feature bits (EAX=07H, ECX=0H)\n");
    eax = 7;
    ecx = 0;
    native_cpuid(&eax, &ebx, &ecx, &edx);
    printf("eax: %x ebx: %x ecx: %x edx: %x\n", eax, ebx, ecx, edx);

    // CPUID.(EAX=07H, ECX=0H):EBX.SGX = 1,
    printf("sgx available: %d\n", (ebx >> 2) & 0x1);

    /* SGX has to be enabled in MSR.IA32_Feature_Control.SGX_Enable
     * check with msr-tools: rdmsr -ax 0x3a
     * SGX_Enable is Bit 18
     * if SGX_Enable = 0 no leaf information will appear.
     * for more information check Intel Docs
     * Architectures-software-developer-system-programming-manual - 35.1
     * Architectural MSRS
     */

    /* CPUID Leaf 12H, Sub-Leaf 0 Enumeration of Intel SGX Capabilities
     * (EAX=12H,ECX=0)
     */
    printf("\nCPUID Leaf 12H, Sub-Leaf 0 of Intel SGX Capabilities (EAX=12H,ECX=0)\n");
    eax = 0x12;
    ecx = 0;
    native_cpuid(&eax, &ebx, &ecx, &edx);
    printf("eax: %x ebx: %x ecx: %x edx: %x\n", eax, ebx, ecx, edx);

    printf("sgx 1 supported: %d\n", eax & 0x1);
    printf("sgx 2 supported: %d\n", (eax >> 1) & 0x1);
    printf("MaxEnclaveSize_Not64: %x\n", edx & 0xFF);
    printf("MaxEnclaveSize_64: %x\n", (edx >> 8) & 0xFF);

    /* CPUID Leaf 12H, Sub-Leaf 1 Enumeration of Intel SGX Capabilities
     * (EAX=12H,ECX=1) */
    printf("\nCPUID Leaf 12H, Sub-Leaf 1 of Intel SGX Capabilities (EAX=12H,ECX=1)\n");
    eax = 0x12;
    ecx = 1;
    native_cpuid(&eax, &ebx, &ecx, &edx);
    printf("eax: %x ebx: %x ecx: %x edx: %x\n", eax, ebx, ecx, edx);

    int i;
    for (i = 2; i < 10; i++) {
        /* CPUID Leaf 12H, Sub-Leaf i Enumeration of Intel SGX Capabilities
         * (EAX=12H,ECX=i) */
        printf("\nCPUID Leaf 12H, Sub-Leaf %d of Intel SGX Capabilities (EAX=12H,ECX=%d)\n", i, i);
        eax = 0x12;
        ecx = i;
        native_cpuid(&eax, &ebx, &ecx, &edx);
        printf("eax: %x ebx: %x ecx: %x edx: %x\n", eax, ebx, ecx, edx);
    }
    return 0;
}
