/* Unit test for issue #92.  
 * Example for use of getsockopt with SO_TYPE 
 * taken from here: http://alas.matf.bg.ac.rs/manuals/lspe/snode=103.html
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <assert.h>

int main(int argc,char **argv) {

  int z;
  int s = -1;                /* Socket */
  int so_type = -1;    /* Socket type */
  socklen_t optlen;  /* Option length */
  int rv;
  
  /*
   * Create a TCP/IP socket to use:
   */
  s = socket(PF_INET,SOCK_STREAM,0);
  if ( s == -1 ) {
    printf("socket(2) error %d", errno);
    exit(-1);
  }

  /*
   * Get socket option SO_SNDBUF:
   */
  optlen = sizeof so_type;
  z = getsockopt(s,SOL_SOCKET,SO_TYPE,
		 &so_type,&optlen);
  if ( z ) {
    printf("getsockopt(s,SOL_SOCKET,"
	    "SO_TYPE) %d", errno);
    exit(-1);
  }
  
  assert(optlen == sizeof so_type);
  if (so_type == SOCK_STREAM) {
    printf("getsockopt: Got socket type OK\n");
  } else {
    printf("getsockopt: Got socket type failed\n");
    rv = -1;
  }
    
  return rv;
}
   
