#include <nv.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>

#include <syslog.h>
#include <stdarg.h>
#include <err.h>

#include <sys/capsicum.h>

#define DH_SERVICE_REMOTE	0
#define DH_SERVICE_LOCAL	1
#define DH_SERVICE_GLOBAL	2

#define DH_CMD_RES_INIT		0
#define DH_CMD_RES_SEARCH	1
#define DH_CMD_GETADDRINFO	2
#define DH_CMD_CONNECT		3
#define DH_CMD_OPEN		4
#define DH_CMD_MKSTEMP		5
#define DH_CMD_CHECKLOCAL	6

#define DH_GETFD_SPOOLDIR	0
#define DH_GETFD_DMACONF	1
#define DH_GETFD_ALIASES	2
#define DH_GETFD_AUTHCONF	3

int dh_res_init(int);
int dh_res_search(int, const char *, int, int, u_char *, int);
int dh_getaddrinfo(int, const char *, const char *, const struct addrinfo *,
    struct addrinfo **);
int dh_connect(int, int *, const struct sockaddr *, socklen_t);
int dh_open(int, const char *, int, int);
int dh_open_locked(int, const char *, int flags, ...);
int dh_getfd(int, int);
int dh_mkstemp(int, char **);
uid_t dh_checklocal(int , const char *);

int dh_service(int, int);
int dh_init(void);
