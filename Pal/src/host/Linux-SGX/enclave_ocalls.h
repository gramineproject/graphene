/*
 * This is for enclave to make ocalls to untrusted runtime.
 */

#include "pal_linux.h"

#include <asm/stat.h>
#include <linux/socket.h>
#include <linux/poll.h>

noreturn void ocall_exit (int exitcode, int is_exitgroup);

int ocall_mmap_untrusted (int fd, uint64_t offset,
                         uint64_t size, unsigned short prot,
                         void ** mem);

int ocall_munmap_untrusted (const void * mem, uint64_t size);

int ocall_cpuid (unsigned int leaf, unsigned int subleaf,
                 unsigned int values[4]);

int ocall_open (const char * pathname, int flags, unsigned short mode);

int ocall_close (int fd);

int ocall_read (int fd, void * buf, unsigned int count);

int ocall_write (int fd, const void * buf, unsigned int count);

int ocall_fstat (int fd, struct stat * buf);

int ocall_fionread (int fd);

int ocall_fsetnonblock (int fd, int nonblocking);

int ocall_fchmod (int fd, unsigned short mode);

int ocall_fsync (int fd);

int ocall_ftruncate (int fd, uint64_t length);

int ocall_lseek(int fd, uint64_t offset, int whence);

int ocall_mkdir (const char *pathname, unsigned short mode);

int ocall_getdents (int fd, struct linux_dirent64 *dirp, unsigned int size);

int ocall_listen (int domain, int type, int protocol,
                       struct sockaddr * addr, unsigned int * addrlen,
                       struct sockopt * opt);

int ocall_accept (int sockfd, struct sockaddr * addr,
                       unsigned int * addrlen, struct sockopt * opt);

int ocall_connect (int domain, int type, int protocol,
                        const struct sockaddr * addr, unsigned int addrlen,
                        struct sockaddr * connaddr,
                        unsigned int * connaddrlen, struct sockopt * opt);

int ocall_recv (int sockfd, void * buf, unsigned int count,
                     struct sockaddr * addr, unsigned int * addrlenptr,
                     void * control, uint64_t * controllenptr);

int ocall_send (int sockfd, const void * buf, unsigned int count,
                     const struct sockaddr * addr, unsigned int addrlen,
                     void * control, uint64_t controllen);

int ocall_setsockopt (int sockfd, int level, int optname,
                       const void * optval, unsigned int optlen);

int ocall_shutdown (int sockfd, int how);

int ocall_resume_thread (void * tcs);

int ocall_clone_thread (void);

int ocall_create_process(const char* uri, int nargs, const char** args, int procfds[3],
                         unsigned int* pid);

int ocall_futex(int* uaddr, int op, int val, int64_t timeout_us);

int ocall_gettime (unsigned long * microsec);

int ocall_sleep (unsigned long * microsec);

int ocall_socketpair (int domain, int type, int protocol, int sockfds[2]);

int ocall_poll(struct pollfd* fds, int nfds, int64_t timeout_us);

int ocall_rename (const char * oldpath, const char * newpath);

int ocall_delete (const char * pathname);

int ocall_load_debug (const char * command);

int ocall_get_attestation(const sgx_spid_t* spid, const char* subkey, bool linkable,
                          const sgx_report_t* report, const sgx_quote_nonce_t* nonce,
                          sgx_attestation_t* attestation);
