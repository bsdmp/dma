#include "dmahelper.h"

/* Internal processing of open() */
/* TODO: we can fork this, then open SPOOLDIR and cap_enter */
/* TODO: save errno only on error */
static void
dh_srv_open(nvlist_t *nvlin, nvlist_t *nvlout)
{
	char *path;
	int flags;
	int mode;
	int ofd;
	FILE *dbg = fopen("/home/misha/dma.debug", "w"); /* !!! */
	if (dbg == NULL) {
	      err(1, "fopen() failed");
	      syslog(LOG_INFO, "dh_getaddrinfo(): fopen() failed");
	}
	nvlist_fdump(nvlin, dbg);

	path = nvlist_take_string(nvlin, "path");
	flags = nvlist_take_number(nvlin, "flags");
	mode = nvlist_take_number(nvlin, "mode");

	if (mode == 0)
		ofd = open(path, flags);
	else
		ofd = open(path, flags, mode);

	nvlist_move_descriptor(nvlout, "ofd", ofd);
	nvlist_add_number(nvlout, "errno", errno);
}

/* External interface for open() */
/* TODO: 'int mode' must be '...' */
int
dh_open(int fd, const char *path, int flags, int mode)
{
	nvlist_t *nvl;
	int ofd;

	nvl = nvlist_create(0);

	nvlist_add_number(nvl, "cmd", DH_CMD_OPEN);
	nvlist_add_string(nvl, "path", path);
	nvlist_add_number(nvl, "flags", flags);
	nvlist_add_number(nvl, "mode", mode);

	nvl = nvlist_xfer(fd, nvl);

	ofd = nvlist_take_descriptor(nvl, "ofd");
	if (ofd == -1)
		errno = nvlist_get_number(nvl, "errno");
	nvlist_destroy(nvl);

	return (ofd);
}

/* Internal processing of connect() */
static void
dh_srv_connect(nvlist_t *nvlin, nvlist_t *nvlout)
{
	int error;
	int s;
	void *name;
	uint64_t namelen;

	s = nvlist_take_descriptor(nvlin, "fd");
	name = nvlist_take_binary(nvlin, "name", &namelen);

	error = connect(s, (struct sockaddr *)name, (socklen_t)namelen);
	if (error != 0)
		goto out;

	nvlist_move_descriptor(nvlout, "fd", s);

out:
	nvlist_add_number(nvlout, "error", error);
	nvlist_add_number(nvlout, "errno", errno);
}

/* External interface for connect() */
/* XXX: original connect() take 's', not '*s' */
/* XXX: errno processing */
int
dh_connect(int fd, int *s, const struct sockaddr *name, socklen_t namelen)
{
	nvlist_t *nvl;
	int error;

	nvl = nvlist_create(0);

	nvlist_add_number(nvl, "cmd", DH_CMD_CONNECT);
	nvlist_move_descriptor(nvl, "fd", *s);
	nvlist_add_binary(nvl, "name", name, namelen);

	nvl = nvlist_xfer(fd, nvl);

	error = nvlist_get_number(nvl, "error");
	if (error != 0)
		goto out;

	*s = nvlist_take_descriptor(nvl, "fd");

out:
	nvlist_destroy(nvl);
	return (error);
}

/* Helper function, taken from libcapsicum */
static struct addrinfo *
addrinfo_unpack(const nvlist_t *nvl)
{
	struct addrinfo *ai;
	const void *addr;
	size_t addrlen;
	const char *canonname = NULL;

	addr = nvlist_get_binary(nvl, "ai_addr", &addrlen);
	ai = malloc(sizeof(*ai) + addrlen);
	if (ai == NULL)
		return (NULL);
	ai->ai_flags = (int)nvlist_get_number(nvl, "ai_flags");
	ai->ai_family = (int)nvlist_get_number(nvl, "ai_family");
	ai->ai_socktype = (int)nvlist_get_number(nvl, "ai_socktype");
	ai->ai_protocol = (int)nvlist_get_number(nvl, "ai_protocol");
	ai->ai_addrlen = (socklen_t)addrlen;
	/* TODO: it was get_string, but it fails if it doesn't exist */
	if (nvlist_exists_string(nvl, "ai_canonname")) {
		ai->ai_canonname = strdup(canonname);
		if (ai->ai_canonname == NULL) {
			free(ai);
			return (NULL);
		}
	} else {
		ai->ai_canonname = NULL;
	}
	ai->ai_addr = (void *)(ai + 1);
	bcopy(addr, ai->ai_addr, addrlen);
	ai->ai_next = NULL;

	return (ai);
}

/* Helper function, taken from casperd */
static nvlist_t *
addrinfo_pack(const struct addrinfo *ai)
{
	nvlist_t *nvl;

	nvl = nvlist_create(0);
	nvlist_add_number(nvl, "ai_flags", ai->ai_flags);
	//if (nvlist_error(nvl) != 0)
		//syslog(LOG_INFO, "==> err ai_flags: %i", nvlist_error(nvl));
	nvlist_add_number(nvl, "ai_family", ai->ai_family);
	//if (nvlist_error(nvl) != 0)
		//syslog(LOG_INFO, "==> err ai_family: %i", nvlist_error(nvl));
	nvlist_add_number(nvl, "ai_socktype", ai->ai_socktype);
	//if (nvlist_error(nvl) != 0)
		//syslog(LOG_INFO, "==> err ai_socktype: %i", nvlist_error(nvl));
	nvlist_add_number(nvl, "ai_protocol", ai->ai_protocol);
	//if (nvlist_error(nvl) != 0)
		//syslog(LOG_INFO, "==> err ai_protocol: %i", nvlist_error(nvl));
	nvlist_add_binary(nvl, "ai_addr", ai->ai_addr, (size_t)ai->ai_addrlen);
	//if (nvlist_error(nvl) != 0)
		//syslog(LOG_INFO, "==> err ai_addr: %i", nvlist_error(nvl));
	if (ai->ai_canonname != NULL)
		nvlist_add_string(nvl, "ai_canonname", ai->ai_canonname);
	//if (nvlist_error(nvl) != 0)
		//syslog(LOG_INFO, "==> err ai_canonname: %i", nvlist_error(nvl));

	return (nvl);
}

/* Internal processing of getaddrinfo() */
static void
dh_srv_getaddrinfo(nvlist_t *nvlin, nvlist_t *nvlout)
{
	struct addrinfo hints, *hintsp, *res, *cur;
	const char *hostname, *servname;
	nvlist_t *elem;
	unsigned int ii;
	int error, family;

	memset(&hints, 0, sizeof(hints));
	hostname = nvlist_get_string(nvlin, "hostname");
	servname = nvlist_get_string(nvlin, "servname");
	if (nvlist_exists_number(nvlin, "hints.ai_flags")) {
		hints.ai_flags = nvlist_get_number(nvlin,
		    "hints.ai_flags");
		hints.ai_family = nvlist_get_number(nvlin,
		    "hints.ai_family");
		hints.ai_socktype = nvlist_get_number(nvlin,
		    "hints.ai_socktype");
		hints.ai_protocol = nvlist_get_number(nvlin,
		    "hints.ai_protocol");
//		hints.ai_addrlen = 0;
//		hints.ai_addr = NULL;
//		hints.ai_canonname = NULL;
		hintsp = &hints;
		family = hints.ai_family;
	} else {
		hintsp = NULL;
		family = AF_UNSPEC;
	}

	error = getaddrinfo(hostname, servname, hintsp, &res);
	//syslog(LOG_INFO, "dh_srv_getaddrinfo error=%i", error);
	if (error != 0)
		goto out;

	for (cur = res, ii = 0; cur != NULL; cur = cur->ai_next, ii++) {
		elem = addrinfo_pack(cur);
		//if (nvlist_error(elem) != 0)
			//syslog(LOG_INFO, "==> dh_srv_getaddrinfo(): %i",
			    //nvlist_error(elem));
		nvlist_movef_nvlist(nvlout, elem, "res%u", ii);
	}

	freeaddrinfo(res);
	error = 0;
out:
	//nvlist_add_string(nvlout, "errstr", gai_strerror(error));
	nvlist_add_number(nvlout, "error", error);
	nvlist_add_number(nvlout, "errno", errno);
}

/* External interface for getaddrinfo(), taken from libcapsicum */
int
dh_getaddrinfo(int fd, const char *hostname, const char *servname,
    const struct addrinfo *hints, struct addrinfo **res)
{
	struct addrinfo *firstai, *prevai, *curai;
	unsigned int ii;
	const nvlist_t *nvlai;
	nvlist_t *nvl;
	int error;

	//FILE *dbg = fopen("/home/misha/dma.debug", "w"); /* !!! */
	//if (dbg == NULL) {
		//err(1, "fopen() failed");
		//syslog(LOG_INFO, "dh_getaddrinfo(): fopen() failed");
	//}

	nvl = nvlist_create(0);
	nvlist_add_number(nvl, "cmd", DH_CMD_GETADDRINFO);
	nvlist_add_string(nvl, "hostname", hostname);
	nvlist_add_string(nvl, "servname", servname);
	if (hints != NULL) {
		nvlist_add_number(nvl, "hints.ai_flags",
		    hints->ai_flags);
		nvlist_add_number(nvl, "hints.ai_family",
		    hints->ai_family);
		nvlist_add_number(nvl, "hints.ai_socktype",
		    hints->ai_socktype);
		nvlist_add_number(nvl, "hints.ai_protocol",
		    hints->ai_protocol);
	}
	nvlist_add_string(nvl, "delimeter", "----");
	//nvlist_fdump(nvl, dbg); /* !!! */
	//syslog(LOG_INFO, "=> dh_getaddrinfo(): send request");
	nvl = nvlist_xfer(fd, nvl);
	//nvlist_fdump(nvl, dbg); /* !!! */
	//syslog(LOG_INFO, "=> dh_getaddrinfo(): got answer");
	//if (nvlist_empty(nvl))
		//syslog(LOG_INFO, "=> dh_getaddrinfo(): got empty!");
	if (nvl == NULL) {
		//syslog(LOG_INFO, "=> dh_getaddrinfo(): got NULL");
		return (EAI_MEMORY);
	}
	if (nvlist_get_number(nvl, "error") != 0) {
		//syslog(LOG_INFO, "dh_getaddrinfo(): got error");
		error = nvlist_get_number(nvl, "error");
		nvlist_destroy(nvl);
		return (error);
	}


	//syslog(LOG_INFO, "dh_getaddrinfo(): start answer processing");
	//nvlist_fdump(nvl, dbg); /* !!! */

	nvlai = NULL;
	firstai = prevai = curai = NULL;
	for (ii = 0; ; ii++) {
		if (!nvlist_existsf_nvlist(nvl, "res%u", ii))
			break;
		nvlai = nvlist_getf_nvlist(nvl, "res%u", ii);
		curai = addrinfo_unpack(nvlai);
		if (curai == NULL)
			break;
		if (prevai != NULL)
			prevai->ai_next = curai;
		else if (firstai == NULL)
			firstai = curai;
		prevai = curai;
	}
	nvlist_destroy(nvl);
	if (curai == NULL && nvlai != NULL) {
		if (firstai == NULL)
			freeaddrinfo(firstai);
		return (EAI_MEMORY);
	}

	*res = firstai;
	return (0);
}

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

	error = nvlist_get_number(nvl, "error");
	if (error != 0)
		goto out;

	answer = nvlist_take_binary(nvl, "answer", &dummy);

out:
	nvlist_destroy(nvl);
	return (error);
}

/* Internal interface for res_init() */
static void
dh_srv_res_init(nvlist_t *nvlout)
{
	int error;

	error = res_init();

	nvlist_add_number(nvlout, "error", error);
};

/* External interface for res_init() */
int
dh_res_init(int fd)
{
	nvlist_t *nvl;

	nvl = nvlist_create(0);
	nvlist_add_number(nvl, "cmd", DH_CMD_RES_INIT);
	nvlist_add_string(nvl, "delimeter", "----");

	nvl = nvlist_xfer(fd, nvl);
	nvlist_destroy(nvl);

	return (0);
}

/* Loop for remtoe services */
static void
dh_srv_remote(int fd)
{
	nvlist_t *nvl, *nvlout;
	int cmd;
	FILE *dbg = fopen("/home/misha/dma2.debug", "w"); /* !!! */
	openlog("dma-srv-remote", LOG_PID | LOG_NDELAY, LOG_MAIL);

	syslog(LOG_INFO, "dh_srv_remote(): new instance");
	while ((nvl = nvlist_recv(fd))) {
		nvlist_fdump(nvl, dbg);
		cmd = nvlist_take_number(nvl, "cmd");
		syslog(LOG_INFO, "=> dh_srv_remote(): got request for cmd=%i", cmd);
		nvlout = nvlist_create(0);

		switch (cmd) {
		case DH_CMD_RES_INIT:
			dh_srv_res_init(nvlout);
			break;
		case DH_CMD_RES_SEARCH:
			dh_srv_res_search(nvl, nvlout);
			break;
		case DH_CMD_GETADDRINFO:
			dh_srv_getaddrinfo(nvl, nvlout);
			break;
		case DH_CMD_CONNECT:
			dh_srv_connect(nvl, nvlout);
			break;
		case DH_CMD_OPEN:
			dh_srv_open(nvl, nvlout);
			break;
		}

		nvlist_fdump(nvlout, dbg);
		syslog(LOG_INFO, "=> dh_srv_remote(): will send answer for cmd=%i",
		    cmd);
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

	syslog(LOG_INFO, "forking new service");

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
