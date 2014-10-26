#include "dmahelper.h"

/* Internal processing of res_search() */
static void
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

/* External interface for res_search() */
int
dh_res_search(int fd, const char *dname, int class, int type, u_char *answer,
    int anslen)
{
	nvlist_t *nvl;
	int error;
	size_t dummy;

	nvl = nvlist_create(0);

	nvlist_add_number(nvl, "cmd", DH_CMD_RES_SEARCH);
	nvlist_add_string(nvl, "dname", dname);
	nvlist_add_number(nvl, "class", class);
	nvlist_add_number(nvl, "type", type);
	nvlist_add_number(nvl, "anslen", anslen);

	nvl = nvlist_xfer(fd, nvl);

	error = nvlist_take_number(nvl, "error");
	if (error != 0)
		goto out;

	answer = nvlist_take_binary(nvl, "answer", &dummy);

out:
	nvlist_destroy(nvl);
	return (error);
}

/* External interface for res_init() */
/* XXX: no internal error processing */
int
dh_res_init(int fd)
{
	nvlist_t *nvl;

	nvl = nvlist_create(0);

	nvlist_add_number(nvl, "cmd", DH_CMD_RES_INIT);
	nvlist_send(fd, nvl); /* xfer? */
	nvlist_destroy(nvl);

	return (0);
}

/* Loop for remtoe services */
static void
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
static void
dh_srv_local(int fd)
{
	nvlist_t *nvl, *nvlout;
	int cmd;

	while ((nvl = nvlist_recv(fd))) {
		cmd = nvlist_take_number(nvl, "cmd");
		nvlout = nvlist_create(0);

		/* SWITCH goes here */

		nvlist_send(fd, nvlout);
		nvlist_destroy(nvlout);
	}
}

/* Start service loop */
static void
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
static void
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

/* Initialiase helper service, returns fd or (-1) on error */
int
dh_service(int fd, int service)
{
	nvlist_t *nvl;
	int srvfd;

	nvl = nvlist_create(0);
	nvlist_add_number(nvl, "service", service);
	nvl = nvlist_xfer(fd, nvl);
	srvfd = nvlist_take_descriptor(nvl, "fd");
	nvlist_destroy(nvl);

	return (srvfd);
}

/* Initialize helper, returns fd or (-1) on error */
int
dh_init(void)
{
	int sv[2];
	pid_t pid;
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
		return (-1);

	pid = fork();
	switch (pid) {
	/* Child */
	case 0:
		close(sv[0]);
		dh_loop(sv[1]);
		exit(0);
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
