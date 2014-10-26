#include <nv.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#define DH_SERVICE_REMOTE 0
#define DH_SERVICE_LOCAL 1

#define DH_CMD_RES_INIT 0
#define DH_CMD_RES_SEARCH 1

int dh_res_init(int);
int dh_res_search(int, const char *, int, int, u_char *, int);

int dh_service(int, int);
int dh_init(void);
