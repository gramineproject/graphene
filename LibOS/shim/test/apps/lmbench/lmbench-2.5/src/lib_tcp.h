#include	<sys/types.h>
#include	<sys/socket.h>
#include	<netinet/in.h>
#include	<netdb.h>
#include	<arpa/inet.h>

int	tcp_server(int prog, int rdwr);
int	tcp_done(int prog);
int	tcp_accept(int sock, int rdwr);
int	tcp_connect(char *host, int prog, int rdwr);
void	sock_optimize(int sock, int rdwr);
int	sockport(int s);
#ifndef	NO_PORTMAPPER
u_short	pmap_getport(struct sockaddr_in *addr, u_long prognum, u_long versnum, u_int protocol);
bool_t	pmap_set(u_long prognum, u_long versnum, u_long protocol, u_short port);
bool_t	pmap_unset(u_long prognum, u_long versnum);
#endif
