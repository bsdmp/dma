/*
 * Copyright (c) 2008-2014, Simon Schubert <2@0x2c.org>.
 * Copyright (c) 2008 The DragonFly Project.  All rights reserved.
 *
 * This code is derived from software contributed to The DragonFly Project
 * by Simon Schubert <2@0x2c.org>.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of The DragonFly Project nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific, prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <errno.h>
#include <netdb.h>
#include <resolv.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <nv.h>
#include <sys/procdesc.h>
#include <sys/capsicum.h>
#include <err.h>

#include "dma.h"

int dh, dhs;
int dh_res_search(int dsh, const char *dname, int class, int type, u_char
    **answer, int anslen);
int
dh_getaddrinfo(int dhs, const char *hostname, const char *servname, const struct addrinfo
    *hints, struct addrinfo **res);

static int
sort_pref(const void *a, const void *b)
{
	const struct mx_hostentry *ha = a, *hb = b;
	int v;

	/* sort increasing by preference primarily */
	v = ha->pref - hb->pref;
	if (v != 0)
		return (v);

	/* sort PF_INET6 before PF_INET */
	v = - (ha->ai.ai_family - hb->ai.ai_family);
	return (v);
}

static int
add_host(int pref, const char *host, int port, struct mx_hostentry **he, size_t *ps)
{
	struct addrinfo hints, *res, *res0 = NULL;
	char servname[10];
	struct mx_hostentry *p;
	const int count_inc = 10;
	int err;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	snprintf(servname, sizeof(servname), "%d", port);
	//err = getaddrinfo(host, servname, &hints, &res0);
	err = dh_getaddrinfo(dhs, host, servname, &hints, &res0);
	if (err)
		return (err == EAI_AGAIN ? 1 : -1);

	for (res = res0; res != NULL; res = res->ai_next) {
		printf("==> add_host(): itteration\n");
		if (*ps + 1 >= roundup(*ps, count_inc)) {
			size_t newsz = roundup(*ps + 2, count_inc);
			*he = reallocf(*he, newsz * sizeof(**he));
			if (*he == NULL)
				goto out;
		}

		p = &(*he)[*ps];
		strlcpy(p->host, host, sizeof(p->host));
		p->pref = pref;
		p->ai = *res;
		p->ai.ai_addr = NULL;
		printf("==> add_host(): before bcopy()\n");
		printf("==> p->ai.ai_addrlen=%i\n", p->ai.ai_addrlen);
		bcopy(res->ai_addr, &p->sa, p->ai.ai_addrlen);

		printf("==> add_host(): will try getnameinfo()\n");
		getnameinfo((struct sockaddr *)&p->sa, p->ai.ai_addrlen,
			    p->addr, sizeof(p->addr),
			    NULL, 0, NI_NUMERICHOST);

		(*ps)++;
	}
	freeaddrinfo(res0);

	return (0);

out:
	if (res0 != NULL)
		freeaddrinfo(res0);
	return (1);
}

int
dns_get_mx_list(const char *host, int port, struct mx_hostentry **he, int no_mx)
{
	char outname[MAXDNAME];
	ns_msg msg;
	ns_rr rr;
	const char *searchhost;
	const unsigned char *cp;
	unsigned char *ans;
	struct mx_hostentry *hosts = NULL;
	size_t nhosts = 0;
	size_t anssz;
	int pref;
	int cname_recurse;
	int have_mx = 0;
	int err;
	int i;

	res_init();
	searchhost = host;
	cname_recurse = 0;

	anssz = 65536;
	ans = malloc(anssz);
	if (ans == NULL)
		return (1);

	if (no_mx)
		goto out;

repeat:
	err = dh_res_search(dhs, searchhost, ns_c_in, ns_t_mx, &ans, anssz);
	printf("dns_get_mx_list: err=%i\n", err);
//	err = res_search(searchhost, ns_c_in, ns_t_mx, ans, anssz);
	if (err < 0) {
		switch (h_errno) {
		case NO_DATA:
			/*
			 * Host exists, but no MX (or CNAME) entry.
			 * Not an error, use host name instead.
			 */
			goto out;
		case TRY_AGAIN:
			/* transient error */
			goto transerr;
		case NO_RECOVERY:
		case HOST_NOT_FOUND:
		default:
			errno = ENOENT;
			goto err;
		}
	}

	if (!ns_initparse(ans, anssz, &msg))
		goto transerr;

	switch (ns_msg_getflag(msg, ns_f_rcode)) {
	case ns_r_noerror:
		break;
	case ns_r_nxdomain:
		goto err;
	default:
		goto transerr;
	}

	for (i = 0; i < ns_msg_count(msg, ns_s_an); i++) {
		printf("=> dns_get_mx_list(): ns_msg_count=%i\n", ns_msg_count(msg, ns_s_an));
		if (ns_parserr(&msg, ns_s_an, i, &rr))
			goto transerr;

		cp = ns_rr_rdata(rr);

		switch (ns_rr_type(rr)) {
		case ns_t_mx:
			have_mx = 1;
			pref = ns_get16(cp);
			cp += 2;
			err = ns_name_uncompress(ns_msg_base(msg), ns_msg_end(msg),
						 cp, outname, sizeof(outname));
			if (err < 0)
				goto transerr;

			err = add_host(pref, outname, port, &hosts, &nhosts);
			printf("=> dns_get_mx_list(): add_host(): %i\n", err);
			if (err == -1)
				goto err;
			break;

		case ns_t_cname:
			err = ns_name_uncompress(ns_msg_base(msg), ns_msg_end(msg),
						 cp, outname, sizeof(outname));
			if (err < 0)
				goto transerr;

			/* Prevent a CNAME loop */
			if (cname_recurse++ > 10)
				goto err;

			searchhost = outname;
			goto repeat;

		default:
			break;
		}
	}

out:
	err = 0;
	if (0) {
transerr:
		if (nhosts == 0)
			err = 1;
	}
	if (0) {
err:
		err = -1;
	}

	free(ans);

	if (err == 0) {
		if (!have_mx) {
			/*
			 * If we didn't find any MX, use the hostname instead.
			 */
			err = add_host(0, host, port, &hosts, &nhosts);
		} else if (nhosts == 0) {
			/*
			 * We did get MX, but couldn't resolve any of them
			 * due to transient errors.
			 */
			err = 1;
		}
	}

	if (nhosts > 0) {
		printf("nhosts > 0\n");
		qsort(hosts, nhosts, sizeof(*hosts), sort_pref);
		/* terminate list */
		*hosts[nhosts].host = 0;
	} else {
		if (hosts != NULL)
			free(hosts);
		hosts = NULL;
	}

	*he = hosts;
	return (err);

	free(ans);
	if (hosts != NULL)
		free(hosts);
	return (err);
}

#define DH_SERVICE_MAIN 0
#define DH_SERVICE_PARSE_CONFIG 1
#define DH_SERVICE_LOADQUEUE 2
#define DH_SERVICE_REMOTE 3
#define DH_SERVICE_LOCAL 4

#define DH_PARSE_CONF 1
#define DH_PARSE_AUTH 2
#define DH_PARSE_ALIAS 3

#define DH_CAPS_DNS	0x00000001
#define DH_CAPS_CONNECT	0x00000002
#define DH_CAPS_OPEN	0x00000004
#define DH_CAPS_MKSTEMP	0x00000008
#define DH_CAPS_SYSLOG	0x00000010

#define DH_CMD_RES_INIT 1
#define DH_CMD_RES_SEARCH 2
#define DH_CMD_GETADDRINFO 3

int
dh_parse(int type)
{
	return (0);
}

/* Fork new process, serving requested service */
int
dh_service(int dh, int type)
{
	nvlist_t *nvl;
	int fd;

	nvl = nvlist_create(0);
	nvlist_add_number(nvl, "service", type);
	nvl = nvlist_xfer(dh, nvl);
	fd = nvlist_take_descriptor(nvl, "fd");
	printf("Success in receiving service fd: %i\n", fd);
	nvlist_destroy(nvl);

	return (fd);
}

int
dh_res_init(int dsh)
{
	nvlist_t *nvl;

	nvl = nvlist_create(0);

	nvlist_add_number(nvl, "command", DH_CMD_RES_INIT);
	printf("Sending dh_res_init\n");
	nvlist_send(dsh, nvl);
	nvlist_destroy(nvl);

	return (0);
}

int
dh_res_search(int dsh, const char *dname, int class, int type, u_char **answer,
    int anslen)
{
	nvlist_t *nvl;
	int error;
	size_t dummy;

	nvl = nvlist_create(0);

	nvlist_add_number(nvl, "command", DH_CMD_RES_SEARCH);
	printf("Sending dh_res_search\n");
	nvlist_add_string(nvl, "dname", dname);
	nvlist_add_number(nvl, "class", class);
	nvlist_add_number(nvl, "type", type);
	nvlist_add_number(nvl, "anslen", anslen);
	nvl = nvlist_xfer(dsh, nvl);
	error = nvlist_take_number(nvl, "error");
	printf("dh_res_search: error=%i\n", error);
	*answer = nvlist_take_binary(nvl, "answer", &dummy);
	nvlist_destroy(nvl);

	return (error);
}

int
dh_getaddrinfo(int dhs, const char *hostname, const char *servname, const struct addrinfo
    *hints, struct addrinfo **res)
{
	nvlist_t *nvl, *nvl0;
	struct addrinfo *res0, *res1, *resf;
	unsigned int i;
	size_t addrlen;
	void *addr;
	int error;

	nvl = nvlist_create(0);
	nvlist_add_number(nvl, "command", DH_CMD_GETADDRINFO);
	nvlist_add_string(nvl, "hostname", hostname);
	nvlist_add_string(nvl, "servname", servname);
	nvlist_add_number(nvl, "hints.ai_flags", hints->ai_flags);
	nvlist_add_number(nvl, "hints.ai_family", hints->ai_family);
	nvlist_add_number(nvl, "hints.ai_socktype", hints->ai_socktype);
	nvlist_add_number(nvl, "hints.ai_protocol", hints->ai_protocol);
	printf("=> dh_getaddrinfo(): send request!\n");
	nvl = nvlist_xfer(dhs, nvl);
	printf("=> dh_getaddrinfo(): received!\n");
	error = (int)nvlist_take_number(nvl, "error");
	if (error != 0)
		return (error);

	for (i = 0; ; i++) {
		if (!nvlist_existsf_nvlist(nvl, "nvl%u", i)) {
			res0->ai_next = NULL;
			break;
		}
		printf("=> dh_getaddrinfo(): i=%i\n", i);

		nvl0 = nvlist_takef_nvlist(nvl, "nvl%u", i);

		addr = nvlist_take_binary(nvl0, "ai_addr", &addrlen);
		printf("=> dh_getaddrinfo(): adrlen=%zu\n", addrlen);

		if (i == 0) {
			res0 = malloc(sizeof(struct addrinfo) + addrlen);
			resf = res0;
		} else {
			res1 = res0;
			res0 = malloc(sizeof(struct addrinfo) + addrlen);
			res1->ai_next = res0;
		}

		res0->ai_flags = (int)nvlist_take_number(nvl0, "ai_flags");
		res0->ai_family = (int)nvlist_take_number(nvl0, "ai_family");
		res0->ai_socktype = (int)nvlist_take_number(nvl0, "ai_socktype");
		res0->ai_protocol = (int)nvlist_take_number(nvl0, "ai_protocol");
		res0->ai_addrlen = (socklen_t)addrlen;
		if (nvlist_exists_string(nvl0, "ai_canonname"))
			res0->ai_canonname = nvlist_take_string(nvl0, "ai_canonname");
		else
			res0->ai_canonname = NULL;

		res0->ai_addr = addr;
		nvlist_destroy(nvl0);
	};

	*res = resf;

	printf("=> dh_getaddrinfo(): %i\n", error);

	return (error);
}

void
dh_loop(int fd)
{
	nvlist_t *nvl, *nvl0;
	int srv;
	pid_t pid;
	int fdp;
	int sv[2];
	int cmd;

	const char *dname;
	int class;
	int type;
	u_char *answer;
	int anslen;
	int error;

	struct addrinfo *res, *res0 = NULL;
	struct addrinfo hints;
	unsigned int i;
	char *hostname;
	char *servname;
	int ai_flags;
	int ai_family;
	int ai_socktype;
	int ai_protocol;
	socklen_t ai_addrlen;
	struct sockaddr *ai_addr;
	char *ai_canonname;
	struct addrinfo *ai_next;

	nvl= nvlist_create(0);

	while ((nvl = nvlist_recv(fd))) {
		srv = nvlist_get_number(nvl, "service");

		pid = fork();
		switch (pid) {
		case 0:
			socketpair(PF_UNIX, SOCK_STREAM, 0, sv);
			/* reuse of nvl */
			nvlist_add_descriptor(nvl, "fd", sv[0]);
			nvlist_send(fd, nvl);
			close(fd);
			close(sv[0]);
			while ((nvl = nvlist_recv(sv[1]))) {
				cmd = nvlist_take_number(nvl, "command");
				switch (cmd) {
				case DH_CMD_RES_INIT:
					printf("Receivied request for dh_res_init\n");
					res_init();
					break;
				case DH_CMD_RES_SEARCH:
					printf("Receivied request for dh_res_search\n");
					dname = nvlist_take_string(nvl, "dname");
					class = nvlist_take_number(nvl, "class");
					type = nvlist_take_number(nvl, "type");
					anslen = nvlist_take_number(nvl, "anslen");
					answer = malloc(anslen);
					error = res_search(dname, class, type, answer, anslen);
					nvlist_add_number(nvl, "error", error);
					nvlist_add_binary(nvl, "answer", answer, anslen);
					nvlist_send(sv[1], nvl);
					break;
				case DH_CMD_GETADDRINFO:
					i = 0;
					printf("Received request for dh_getaddrinfo\n");
					/* TODO: checkout other hints fields! */
					/* TODO: freeaddr() */
					memset(&hints, 0, sizeof(hints));
					hostname = nvlist_take_string(nvl, "hostname");
					servname = nvlist_take_string(nvl, "servname");
					hints.ai_flags = (int)nvlist_take_number(nvl, "hints.ai_flags");
					hints.ai_family = (int)nvlist_take_number(nvl, "hints.ai_family");
					hints.ai_socktype = (int)nvlist_take_number(nvl, "hints.ai_socktype");
					hints.ai_protocol = (int)nvlist_take_number(nvl, "hints.ai_protocol");
					printf("hostname: %s\nservname: %s\n", hostname, servname);
					nvlist_destroy(nvl);
					nvl = nvlist_create(0);
					if ((error = getaddrinfo(hostname, servname, &hints, &res)) == 0) {
						res0 = res;
						for (; res0->ai_next != NULL; ) {
							printf("DH_CMD_GETADDRINFO: i=%i\n", i);
							nvl0 = nvlist_create(0);

							nvlist_add_number(nvl0, "ai_flags", (uint64_t)res0->ai_flags);
							nvlist_add_number(nvl0, "ai_family", (uint64_t)res0->ai_family);
							nvlist_add_number(nvl0, "ai_socktype", (uint64_t)res0->ai_socktype);
							nvlist_add_number(nvl0, "ai_protocol", (uint64_t)res0->ai_protocol);
							nvlist_add_number(nvl0, "ai_addrlen", (uint64_t)res0->ai_addrlen);
							if (res0->ai_canonname != NULL)
								nvlist_add_string(nvl0, "ai_canonname", res0->ai_canonname);
							nvlist_add_binary(nvl0, "ai_addr", res0->ai_addr, (size_t)res0->ai_addrlen);
							if (nvlist_error(nvl0) != 0)
								err(1, "nvlist_error1");

							nvlist_movef_nvlist(nvl, nvl0, "nvl%u", i);
							if (nvlist_error(nvl) != 0)
								err(1, "nvlist_error2");
							i++;
							res0 = res0->ai_next;
						};
						if (res0->ai_next == NULL)
							printf("res0->ai_next == NULL\n");
					} else {
						err(1, "getaddrinfo");
					};
					nvlist_add_number(nvl, "error", (uint64_t)error);
					printf("Sending!\n");
					nvlist_send(sv[1], nvl);
					break;
				default:
					printf("Unknown command receivied!\n");
				}
			}

		}

	}
	if (nvl == NULL)
		err(1, "dh_loop: nvlist_recv() failed");
	exit(0);
}

int
dh_init(void)
{
	int sv[2];
	pid_t pid;
	int fdp;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1)
		return (-1);
//	printf("New fd: %i\n", sv[0]);
//	printf("New fd: %i\n", sv[1]);

	pid = fork();
	switch (pid) {
	/* Child */
	case 0:
		close(sv[0]);
		dh_loop(sv[1]);
		return (-1);
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

int
main(int argc, char **argv)
{
	struct mx_hostentry *he, *p;
	int err;
	nvlist_t *nvl;

	dh = dh_init();
	cap_enter();
	if (cap_sandboxed())
		printf("capability mode sandbox enabled\n");
	dhs = dh_service(dh, DH_SERVICE_REMOTE);
	dh_res_init(dhs);

	err = dns_get_mx_list(argv[1], 53, &he, 0);
	printf("main: err=%i\n", err);
	if (err)
		return (err);

	for (p = he; *p->host != 0; p++) {
		printf("%d\t%s\t%s\n", p->pref, p->host, p->addr);
	}

	return (0);
}
