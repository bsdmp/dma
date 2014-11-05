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
#define DH_CMD_GETPWNAM		6
#define DH_CMD_GETPWUID		7
#define DH_CMD_OPENLOG		8
#define DH_CMD_SYSLOG		9
#define DH_CMD_CLOSELOG		10
#define DH_CMD_GETHOSTNAME	11

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
struct passwd *dh_getpwnam(int, const char *);
struct passwd *dh_getpwuid(int, uid_t);
void dh_openlog(int, const char *, int logopt, int facility);
void dh_syslog(int, int, const char *, ...);
void dh_closelog(int);
int dh_gethostname(int, char *, size_t);

int dh_service(int, int);
int dh_init(void);
