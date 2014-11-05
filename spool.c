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

#include "dfcompat.h"

#include <sys/file.h>
#include <sys/stat.h>

#include <ctype.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <unistd.h>
#include <syslog.h>

#include "dma.h"

/*
 * Spool file format:
 *
 * 'Q'id files (queue):
 *   Organized like an RFC822 header, field: value.  Ignores unknown fields.
 *   ID: id
 *   Sender: envelope-from
 *   Recipient: envelope-to
 *
 * 'M'id files (data):
 *   mail data
 *
 * Each queue file needs to have a corresponding data file.
 * One data file might be shared by linking it several times.
 *
 * Queue ids are unique, formed from the inode of the data file
 * and a unique identifier.
 */

int
newspoolf(struct queue *queue)
{
	char *fn;
	struct stat st;
	struct stritem *t;
	int fd;

	fn = malloc(PATH_MAX+1);

	if (snprintf(fn, sizeof(fn), "%s", "tmp_XXXXXXXXXX") <= 0)
		return (-1);

	fd = dh_mkstemp(dhs, &fn);
	if (fd < 0)
		return (-1);
	/* XXX group rights */
	if (fchmod(fd, 0660) < 0)
		goto fail;
	if (flock(fd, LOCK_EX) == -1)
		goto fail;
	queue->tmpf = strdup(fn);
	if (queue->tmpf == NULL)
		goto fail;

	/*
	 * Assign queue id
	 */
	if (fstat(fd, &st) != 0)
		goto fail;
	if (asprintf(&queue->id, "%"PRIxMAX, (uintmax_t)st.st_ino) < 0)
		goto fail;

	queue->mailf = fdopen(fd, "r+");
	if (queue->mailf == NULL)
		goto fail;

	t = malloc(sizeof(*t));
	if (t != NULL) {
		t->str = queue->tmpf;
		SLIST_INSERT_HEAD(&tmpfs, t, next);
	}
	return (0);

fail:
	if (queue->mailf != NULL)
		fclose(queue->mailf);
	close(fd);
	unlinkat(spoolfd, fn, 0);
	return (-1);
}

static int
writequeuef(struct qitem *it)
{
	int error;
	int queuefd;

	/* CAP: open, flock */
	//queuefd = dh_open_locked(dhsl, it->queuefn, O_CREAT|O_EXCL|O_RDWR, 0660);
	queuefd = openat_locked(spoolfd, it->queuefn, O_CREAT|O_EXCL|O_RDWR, 0660);
	if (queuefd == -1)
		return (-1);
	if (fchmod(queuefd, 0660) < 0)
		return (-1);
	it->queuef = fdopen(queuefd, "w+");
	if (it->queuef == NULL)
		return (-1);

	error = fprintf(it->queuef,
			"ID: %s\n"
			"Sender: %s\n"
			"Recipient: %s\n",
			 it->queueid,
			 it->sender,
			 it->addr);

	if (error <= 0)
		return (-1);

	if (fflush(it->queuef) != 0 || fsync(fileno(it->queuef)) != 0)
		return (-1);

	return (0);
}

static struct qitem *
readqueuef(struct queue *queue, char *queuefn)
{
	char line[1000];
	struct queue itmqueue;
	FILE *queuef = NULL;
	char *s;
	char *queueid = NULL, *sender = NULL, *addr = NULL;
	struct qitem *it = NULL;
	int queuefd;

	bzero(&itmqueue, sizeof(itmqueue));
	LIST_INIT(&itmqueue.queue);

	/* XXX error checking */
	queuefd = openat(spoolfd, it->queuefn, O_RDONLY);
	if (queuefd < 0)
		goto out;
	queuef = fdopen(queuefd, "r");
	if (queuef == NULL)
		goto out;

	while (!feof(queuef)) {
		if (fgets(line, sizeof(line), queuef) == NULL || line[0] == 0)
			break;
		line[strlen(line) - 1] = 0;	/* chop newline */

		s = strchr(line, ':');
		if (s == NULL)
			goto malformed;
		*s = 0;

		s++;
		while (isspace(*s))
			s++;

		s = strdup(s);
		if (s == NULL)
			goto malformed;

		if (strcmp(line, "ID") == 0) {
			queueid = s;
		} else if (strcmp(line, "Sender") == 0) {
			sender = s;
		} else if (strcmp(line, "Recipient") == 0) {
			addr = s;
		} else {
			dh_syslog(dhs, LOG_DEBUG, "ignoring unknown queue info `%s' in `%s'",
			       line, queuefn);
			free(s);
		}
	}

	if (queueid == NULL || sender == NULL || addr == NULL ||
	    *queueid == 0 || *addr == 0) {
malformed:
		errno = EINVAL;
		dh_syslog(dhs, LOG_ERR, "malformed queue file `%s'", queuefn);
		goto out;
	}

	if (add_recp(&itmqueue, addr, 0) != 0)
		goto out;

	it = LIST_FIRST(&itmqueue.queue);
	it->sender = sender; sender = NULL;
	it->queueid = queueid; queueid = NULL;
	it->queuefn = queuefn; queuefn = NULL;
	LIST_INSERT_HEAD(&queue->queue, it, next);

out:
	if (sender != NULL)
		free(sender);
	if (queueid != NULL)
		free(queueid);
	if (addr != NULL)
		free(addr);
	if (queuef != NULL)
		fclose(queuef);

	return (it);
}

int
linkspool(struct queue *queue)
{
	struct stat st;
	struct qitem *it;

	if (fflush(queue->mailf) != 0 || fsync(fileno(queue->mailf)) != 0)
		goto delfiles;

	dh_syslog(dhs, LOG_INFO, "new mail from user=%s uid=%d envelope_from=<%s>",
	       username, getuid(), queue->sender);

	LIST_FOREACH(it, &queue->queue, next) {
		if (asprintf(&it->queueid, "%s.%"PRIxPTR, queue->id, (uintptr_t)it) <= 0)
			goto delfiles;
		if (asprintf(&it->queuefn, "Q%s", it->queueid) <= 0)
			goto delfiles;
		if (asprintf(&it->mailfn, "M%s", it->queueid) <= 0)
			goto delfiles;

		/* Neither file may not exist yet */
		if (fstatat(spoolfd, it->queuefn, &st, 0) == 0 ||
		    fstatat(spoolfd, it->mailfn, &st, 0) == 0)
			goto delfiles;

		if (writequeuef(it) != 0) /* CAP+: open, fsync, fflush */
			goto delfiles;

		if (linkat(spoolfd, queue->tmpf, spoolfd, it->mailfn, 0) != 0)
			goto delfiles;
	}

	LIST_FOREACH(it, &queue->queue, next) {
		dh_syslog(dhs, LOG_INFO, "mail to=<%s> queued as %s",
		       it->addr, it->queueid);
	}

	unlinkat(spoolfd, queue->tmpf, 0);
	return (0);

delfiles:
	LIST_FOREACH(it, &queue->queue, next) {
		unlinkat(spoolfd, it->mailfn, 0);
		unlinkat(spoolfd, it->queuefn, 0);
	}
	return (-1);
}

int
load_queue(struct queue *queue)
{
	struct stat sb;
	struct qitem *it;
	DIR *spooldir;
	struct dirent *de;
	char *queuefn;
	char *mailfn;

	bzero(queue, sizeof(*queue));
	LIST_INIT(&queue->queue);

	spooldir = fdopendir(spoolfd);
	if (spooldir == NULL)
		err(1, "reading queue");

	while ((de = readdir(spooldir)) != NULL) {
		queuefn = NULL;
		mailfn = NULL;

		/* ignore non-queue files */
		if (de->d_name[0] != 'Q')
			continue;
		if (asprintf(&queuefn, "Q%s", de->d_name + 1) < 0)
			goto fail;
		if (asprintf(&mailfn, "M%s", de->d_name + 1) < 0)
			goto fail;

		/*
		 * Some file systems don't provide a de->d_type, so we have to
		 * do an explicit stat on the queue file.
		 * Move on if it turns out to be something else than a file.
		 */
		if (fstatat(spoolfd, queuefn, &sb, 0) != 0)
			goto skip_item;
		if (!S_ISREG(sb.st_mode)) {
			errno = EINVAL;
			goto skip_item;
		}

		if (fstatat(spoolfd, mailfn, &sb, 0) != 0)
			goto skip_item;

		it = readqueuef(queue, queuefn); /* CAP: fopen */
		if (it == NULL)
			goto skip_item;

		it->mailfn = mailfn;
		continue;

skip_item:
		dh_syslog(dhs, LOG_INFO, "could not pick up queue file: `%s'/`%s': %s", queuefn, mailfn, strerror(errno));
		if (queuefn != NULL)
			free(queuefn);
		if (mailfn != NULL)
			free(mailfn);
	}
	closedir(spooldir);
	return (0);

fail:
	return (-1);
}

void
delqueue(struct qitem *it)
{
	unlinkat(spoolfd, it->mailfn, 0);
	unlinkat(spoolfd, it->queuefn, 0);
	if (it->queuef != NULL)
		fclose(it->queuef);
	if (it->mailf != NULL)
		fclose(it->mailf);
	free(it);
}

int
acquirespool(struct qitem *it)
{
	int queuefd;
	int mailfd;

	if (it->queuef == NULL) {
		queuefd = openat_locked(spoolfd, it->queuefn, O_RDWR|O_NONBLOCK);
		if (queuefd < 0)
			goto fail;
		it->queuef = fdopen(queuefd, "r+");
		if (it->queuef == NULL)
			goto fail;
	}

	if (it->mailf == NULL) {
		/* XXX: changed to use open() and fdopen() */
		mailfd = openat(spoolfd, it->mailfn, O_RDONLY, 0);
		if (mailfd < 0)
			goto fail;
		it->mailf = fdopen(mailfd, "r");
//		it->mailf = fopen(it->mailfn, "r");
		if (it->mailf == NULL)
			goto fail;
	}

	return (0);

fail:
	if (errno == EWOULDBLOCK)
		return (1);
	dh_syslog(dhs, LOG_INFO, "could not acquire queue file: %s", strerror(errno));
	return (-1);
}

void
dropspool(struct queue *queue, struct qitem *keep)
{
	struct qitem *it;

	LIST_FOREACH(it, &queue->queue, next) {
		if (it == keep)
			continue;

		if (it->queuef != NULL)
			fclose(it->queuef);
		if (it->mailf != NULL)
			fclose(it->mailf);
	}
}

int
flushqueue_since(unsigned int period)
{
        struct stat st;
	struct timeval now;
        char *flushfn = NULL;

	if (asprintf(&flushfn, "%s", SPOOL_FLUSHFILE) < 0)
		return (0);
	if (fstatat(spoolfd, flushfn, &st, 0) < 0) {
		free(flushfn);
		return (0);
	}
	free(flushfn);
	flushfn = NULL;
	if (gettimeofday(&now, 0) != 0)
		return (0);

	/* Did the flush file get touched within the last period seconds? */
	if (st.st_mtim.tv_sec + period >= now.tv_sec)
		return (1);
	else
		return (0);
}

int
flushqueue_signal(void)
{
        char *flushfn = NULL;
	int fd;

        if (asprintf(&flushfn, "%s", SPOOL_FLUSHFILE) < 0)
		return (-1);
	fd = openat(spoolfd, flushfn, O_CREAT|O_WRONLY|O_TRUNC, 0660);
	free(flushfn);
	if (fd < 0) {
		dh_syslog(dhs, LOG_ERR, "could not open flush file: %s", strerror(errno));
		return (-1);
	}
        close(fd);
	return (0);
}
