/* lib_unix.c */
#ifndef	_LIB_UNIX_H_
#define	_LIB_UNIX_H_
int unix_server(char *path);
int unix_done(int sock, char *path);
int unix_accept(int sock);
int unix_connect(char *path);
#endif
