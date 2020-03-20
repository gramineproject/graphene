/*
 * This is for enclave to make ocalls to untrusted runtime.
 */

#include "pal_linux.h"

#include <asm/stat.h>
#include <linux/socket.h>
#include <linux/poll.h>
#include <sys/types.h>

noreturn void ocall_exit (int exitcode, int is_exitgroup);

int ocall_mmap_untrusted (int fd, uint64_t offset,
                          uint64_t size, unsigned short prot,
                          void ** mem);

int ocall_munmap_untrusted (const void * mem, uint64_t size);

int ocall_cpuid (unsigned int leaf, unsigned int subleaf,
                 unsigned int values[4]);

int ocall_open (const char * pathname, int flags, unsigned short mode);

int ocall_close (int fd);

ssize_t ocall_read(int fd, void* buf, size_t count);

ssize_t ocall_write(int fd, const void* buf, size_t count);

ssize_t ocall_pread(int fd, void* buf, size_t count, off_t offset);

ssize_t ocall_pwrite(int fd, const void* buf, size_t count, off_t offset);

int ocall_fstat (int fd, struct stat * buf);

int ocall_fionread (int fd);

int ocall_fsetnonblock (int fd, int nonblocking);

int ocall_fchmod (int fd, unsigned short mode);

int ocall_fsync (int fd);

int ocall_ftruncate (int fd, uint64_t length);

int ocall_mkdir (const char *pathname, unsigned short mode);

int ocall_getdents (int fd, struct linux_dirent64 *dirp, unsigned int size);

int ocall_listen(int domain, int type, int protocol, int ipv6_v6only,
                 struct sockaddr* addr, unsigned int* addrlen, struct sockopt* sockopt);

int ocall_accept (int sockfd, struct sockaddr * addr,
                  unsigned int * addrlen, struct sockopt * opt);

int ocall_connect(int domain, int type, int protocol, int ipv6_v6only,
                  const struct sockaddr* addr, unsigned int addrlen,
                  struct sockaddr* bind_addr, unsigned int* bind_addrlen,
                  struct sockopt* sockopt);

ssize_t ocall_recv(int sockfd, void* buf, size_t count,
                   struct sockaddr* addr, unsigned int* addrlenptr,
                   void* control, uint64_t* controllenptr);

ssize_t ocall_send(int sockfd, const void* buf, size_t count,
                   const struct sockaddr* addr, unsigned int addrlen,
                   void* control, uint64_t controllen);

int ocall_setsockopt (int sockfd, int level, int optname,
                      const void * optval, unsigned int optlen);

int ocall_shutdown (int sockfd, int how);

int ocall_resume_thread (void * tcs);

int ocall_clone_thread (void);

int ocall_create_process(const char* uri, int nargs, const char** args, int* stream_fd, unsigned int* pid);

int ocall_futex(int* uaddr, int op, int val, int64_t timeout_us);

int ocall_gettime (unsigned long * microsec);

int ocall_sleep (unsigned long * microsec);

int ocall_socketpair (int domain, int type, int protocol, int sockfds[2]);

int ocall_poll(struct pollfd* fds, int nfds, int64_t timeout_us);

int ocall_rename (const char * oldpath, const char * newpath);

int ocall_delete (const char * pathname);

int ocall_load_debug (const char * command);

int ocall_eventfd (unsigned int initval, int flags);

/*!
 * \brief Execute untrusted code in PAL to obtain a quote from the Quoting Enclave.
 *
 * The obtained quote is not validated in any way (i.e., this function does not check whether the
 * returned quote corresponds to this enclave or whether its contents make sense).
 *
 * \param[in]  spid       Software provider ID (SPID).
 * \param[in]  linkable   Quote type (linkable vs unlinkable).
 * \param[in]  report     Enclave report to be sent to the Quoting Enclave.
 * \param[in]  nonce      16B nonce to be included in the quote for freshness.
 * \param[out] quote      Quote returned by the Quoting Enclave (allocated via malloc() in this
 *                        function; the caller gets the ownership of the quote).
 * \param[out] quote_len  Length of the quote returned by the Quoting Enclave.
 * \return                0 on success, negative Linux error code otherwise.
 */
int ocall_get_quote(const sgx_spid_t* spid, bool linkable, const sgx_report_t* report,
                    const sgx_quote_nonce_t* nonce, char** quote, size_t* quote_len);
