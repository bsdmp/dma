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

/* dma helper for res_search() */
void
dh_srv_res_search(nvlist_t *nvlin, nvlist_t *nvlout)
{
	const char *dname;
	int class;
	int type;
	u_char *answer;
	int anslen;
	int error;

	dname = nvlist_take_string(nvlin, "dname");
	class = nvlist_take_number(nvlin, "class");
	type = nvlist_take_number(nvlin, "type");
	anslen = nvlist_take_number(nvlin, "anslen");
	answer = malloc(anslen);
	error = res_search(dname, class, type, answer, anslen);
	nvlist_add_number(nvlout, "error", error);
	nvlist_add_binary(nvlout, "answer", answer, anslen);
}

/* Loop for remtoe services */
void
dh_srv_remote(int fd)
{
	nvlist_t *nvl, *nvlout;
	int cmd;

	while ((nvl = nvlist_recv(fd))) {
		cmd = nvlist_take_number(nvl, "cmd");
		nvlout = nvlist_create(0);

		switch (cmd) {
		case DH_CMD_RES_INIT:
			/* special handler for this? (errors) */
			res_init();
			break;
		case DH_CMD_RES_SEARCH:
			dh_srv_res_search(nvl, nvlout);
			break;
		}

		nvlist_send(fd, nvlout);
		nvlist_destroy(nvlout);
	}
}

/* Loop for local services */
void
dh_srv_local(int fd)
{
}

/* Start service loop */
void
dh_srv_dispatch(int fd, int service)
{
	switch (service) {
	case DH_SERVICE_REMOTE:
		dh_srv_remote(fd);
		break;
	case DH_SERVICE_LOCAL:
		dh_srv_local(fd);
		break;
	}

	exit(0);
}

/* Loop of the main helper responsible for forking services */
void
dh_loop(int fd)
{
	nvlist_t *nvl;
	int service;
	int sv[2];
	pid_t pid;

	while ((nvl = nvlist_recv(fd))) {
		service = nvlist_take_number(nvl, "service");

		if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
			nvlist_add_number(nvl, "error", 1);
			nvlist_send(fd, nvl);
			continue;
		}

		pid = fork();
		switch (pid) {
		case 0:
			close(sv[1]);
			dh_srv_dispatch(sv[0], service);
			break;
		default:
			nvlist_move_descriptor(nvl, "fd", sv[1]);
			nvlist_send(fd, nvl);
		}
	}
}

/* Initialize helper, returns fd or (-1) on error */
int
dh_init(void)
{
	int sv[2];
	pid_t pid;
	int fdp;
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
		return (-1);

	pid = fork();
	switch (pid) {
	/* Child */
	case 0:
		close(sv[0]);
		dh_loop(sv[1]);
		return (-1);
	/* Error */
	case -1:
		close(sv[0]);
		close(sv[1]);
		return (-1);
	/* Parrent */
	default:
		close(sv[1]);
		return (sv[0]);
	}
}
