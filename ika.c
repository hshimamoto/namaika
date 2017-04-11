#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

static struct sockaddr_in proxyaddr;
static struct sockaddr_in bindaddr;
static int bindport = 8080;

#define BUFSZ	(2 * 1024 * 1024)

static time_t now;

int lookup_addr_in(const char *host, const char *port,
		   struct sockaddr_in *addr)
{
	struct addrinfo hints, *res;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(host, port, &hints, &res) != 0)
		return -1;

	memcpy(addr, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);

	return 0;
}

struct http_connection {
	int sock;
	int close;
	int rflag;
	time_t last;
	char rbuf[BUFSZ];
	int rlen;
};

static int http_connection_readbuf(struct http_connection *conn)
{
	int rest, rlen;
	int curr;

	if (conn->sock < 0)
		return -1; /* no sock */

	if (conn->rflag == 0)
		return conn->rlen; /* not readable */

	curr = conn->rlen;
	if (curr < 0)
		curr = 0;

	rest = BUFSZ - curr - 1;
	if (rest <= 0)
		return conn->rlen; /* max */

	rlen = read(conn->sock, conn->rbuf + curr, rest);
	if (rlen <= 0) {
		close(conn->sock);
		conn->sock = -1;
		conn->close = 1;
		return conn->rlen; /* return current len */
	}

	conn->rlen = curr + rlen;
	conn->rbuf[conn->rlen] = '\0';

	conn->last = now;

	return conn->rlen;
}

static void http_connection_bufclear(struct http_connection *conn)
{
	conn->rbuf[0] = 0;
	conn->rlen = -1;
}

static int http_connection_send(struct http_connection *conn,
				char *buf, int len)
{
	if (conn->sock < 0)
		return -1;

	conn->last = now;

	return write(conn->sock, buf, len);
}

static void http_connection_close(struct http_connection *conn)
{
	if (conn->sock < 0)
		return;
	close(conn->sock);
	conn->sock = -1;
	conn->close = 1;
}

struct http_connection *new_http_connection(int sock)
{
	struct http_connection *conn;

	conn = malloc(sizeof(*conn));
	memset(conn, 0, sizeof(*conn));
	conn->sock = sock;
	conn->last = now;
	http_connection_bufclear(conn);

	return conn;
}

void delete_http_connection(struct http_connection *conn)
{
	free(conn);
}

static uint32_t httpclient_ids;
static uint32_t nr_httpclients;

struct httpclient {
	struct httpclient *next;
	/* params */
	int status;
	int dead;
	uint32_t id;
	/* connections */
	struct http_connection *local, *remote;
	/* reqline */
	char reqline[4096];
	int hdrptr;
};

enum {
	HCLI_ST_INIT = 0,
	HCLI_ST_CONNECTING = 1,
	HCLI_ST_CONNECTED = 2,
};

static void handle_httpclient_local_connect(struct httpclient *cli)
{
	char *rbuf = cli->local->rbuf;

	char *req = rbuf;
	char *crlf, *sep;

	crlf = strstr(req, "\r\n");
	sep = strstr(req, "\r\n\r\n");

	/* header done */
	if (!sep)
		return;

	/* req type ok? */
	int method = -1;

	if (!strncmp(req, "GET", 3))
		method = 0;
	else if (!strncmp(req, "POST", 4))
		method = 1;
	else if (!strncmp(req, "PUT", 3))
		method = 2;
	else if (!strncmp(req, "DELETE", 6))
		method = 3;
	else if (!strncmp(req, "HEAD", 4))
		method = 4;
	else if (!strncmp(req, "CONNECT", 7))
		method = 5;
	else {
		printf("unknown request\n");
		return; /* close? */
	}

	/* copy request line */

	char *header = crlf + 2;

	*crlf = '\0';

	puts(req);

	char *host, *port, *proto;
	char *path = NULL;

	char *x = req;

	while (*x != ' ')
		x++;
	*x = '\0';
	x++;
	host = x;
	if (method != 5) {
		port = "80";
		host += 7; /* http:// */
	} else {
		port = "443";
	}

	x = host + 1;
	while (*x != ' ') {
		if (*x == ':') {
			*x = '\0';
			port = x + 1;
		} else if (!path && *x == '/') {
			*x = '\0';
			path = x + 1;
		}
		x++;
	}
	*x = '\0';
	proto = ++x;
	if (!path)
		path = "";

	/* lookup */
	struct sockaddr_in addr;

	printf("host:%s port:%s\n", host, port);
	if (lookup_addr_in(host, port, &addr) == -1) {
		printf("lookup addr error\n");
		return;
	}

	unsigned int ii;

	ii = addr.sin_addr.s_addr;

	char connline[4096];
	char ip[64];

	sprintf(ip, "%u.%u.%u.%u",
		ii & 0xff,
		(ii >> 8) & 0xff,
		(ii >> 16) & 0xff,
		(ii >> 24) & 0xff);

	sprintf(connline, "CONNECT %s:%s HTTP/1.0\r\n\r\n", ip, port);
	printf("%s -> %s", host, connline);

	http_connection_send(cli->remote, connline, strlen(connline));
	if (method == 5) {/* CONNECT */
		/* browser should handle after CONNECT */
		cli->status = HCLI_ST_CONNECTED;
		http_connection_bufclear(cli->local);
		return;
	}

	/* wait a CONNECT */
	cli->status = HCLI_ST_CONNECTING;

	/* setup request */
	sprintf(cli->reqline, "%s /%s %s\r\n", req, path, proto);
	cli->hdrptr = header - req;
}

static void handle_httpclient_local(struct httpclient *cli)
{
	struct http_connection *conn = cli->local;
	int rlen;

	if (cli->remote->close)
		http_connection_close(conn);

	if ((now - conn->last) > 60)
		http_connection_close(conn);

	rlen = http_connection_readbuf(conn);
	if (rlen < 0)
		return; /* closed */

	//puts(conn->rbuf);

	switch (cli->status) {
	case HCLI_ST_INIT:
		handle_httpclient_local_connect(cli);
		return;
	case HCLI_ST_CONNECTING:
		return; /* waiting */
	case HCLI_ST_CONNECTED:
		http_connection_send(cli->remote, conn->rbuf, conn->rlen);
		break;
	}

	http_connection_bufclear(conn);
}

static int handle_httpclient_remote_connecting(struct httpclient *cli)
{
	struct http_connection *conn = cli->remote;
	char *rbuf = conn->rbuf;
	char *sep;

	sep = strstr(rbuf, "\r\n\r\n");

	if (!sep)
		return 0;

	if (strncmp(rbuf, "HTTP/1", 6))
		return -1; /* TODO: handle bad request */
	if (strncmp(rbuf + 9, "200", 3))
		return -1; /* TODO: handle bad request */

	http_connection_send(conn, cli->reqline, strlen(cli->reqline));
	http_connection_send(conn,
			     cli->local->rbuf + cli->hdrptr,
			     cli->local->rlen - cli->hdrptr);
	http_connection_bufclear(cli->local);

	http_connection_bufclear(conn);

	cli->status = HCLI_ST_CONNECTED;

	return 0;
}

static void handle_httpclient_remote(struct httpclient *cli)
{
	struct http_connection *conn = cli->remote;
	int rlen;

	if (cli->local->close)
		http_connection_close(conn);

	if ((now - conn->last) > 60)
		http_connection_close(conn);

	rlen = http_connection_readbuf(conn);
	if (rlen < 0)
		return; /* closed */

	//puts(conn->rbuf);

	if (cli->status == HCLI_ST_CONNECTING) {
		handle_httpclient_remote_connecting(cli);
		return;
	}

	http_connection_send(cli->local, conn->rbuf, conn->rlen);
	http_connection_bufclear(conn);
}

static void handle_httpclient(struct httpclient *cli)
{
	handle_httpclient_local(cli);
	handle_httpclient_remote(cli);

	if (cli->local->sock == -1 &&
	    cli->remote->sock == -1)
		cli->dead = 1;
}

static struct httpclient *new_httpclient(int local, int remote)
{
	struct httpclient *cli;

	cli = malloc(sizeof(*cli));
	memset(cli, 0, sizeof(*cli));
	cli->status = HCLI_ST_INIT;

	/* sentinel */
	if (local == -1 && remote == -1)
		return cli;

	cli->id = httpclient_ids++;
	printf("new httpclient %u\n", cli->id);
	++nr_httpclients;

	if (local >= 0)
		cli->local = new_http_connection(local);
	if (remote >= 0)
		cli->remote = new_http_connection(remote);

	return cli;
}

static void delete_httpclient(struct httpclient *cli)
{
	printf("delete httpclient %u\n", cli->id);
	--nr_httpclients;

	delete_http_connection(cli->local);
	delete_http_connection(cli->remote);
	free(cli);
}

static int bind_localhttp(void)
{
	int s, one;

	s = socket(AF_INET, SOCK_STREAM, 0);
	one = 1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	bind(s, (struct sockaddr *)&bindaddr, sizeof(bindaddr));
	listen(s, 5);

	return s;
}

static struct httpclient *accept_localhttp(int s)
{
	struct httpclient *cli;
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	int local, remote;

	memset(&addr, 0, len);
	local = accept(s, (struct sockaddr *)&addr, &len);
	if (local == -1)
		return NULL;

	/* connect to proxy */
	remote = socket(AF_INET, SOCK_STREAM, 0);
	if (remote == -1)
		goto local_err;
	if (connect(remote,
			(struct sockaddr *)&proxyaddr, sizeof(proxyaddr)) < 0) {
		goto remote_err;
	}

	cli = new_httpclient(local, remote);
	if (cli)
		return cli;

remote_err:
	close(remote);
local_err:
	close(local);

	return NULL;
}

static int http_connection_fdset(struct http_connection *conn, fd_set *fds)
{
	if (conn->sock < 0)
		return -1;
	FD_SET(conn->sock, fds);

	return conn->sock;
}

static void http_connection_fd_flag(struct http_connection *conn, fd_set *fds)
{
	if (conn->sock < 0)
		return;
	conn->rflag = !!FD_ISSET(conn->sock, fds);
}

void localhttp(void)
{
	int s;
	struct httpclient *head, *last;
	fd_set fds;
	int max;

	s = bind_localhttp();

	/* sentinel */
	head = new_httpclient(-1, -1);
	last = new_httpclient(-1, -1);
	head->next = last;

	max = s + 1;
	for (;;) {
		struct timeval tv;
		int ret;
		struct httpclient *cli;

		now = time(NULL);

		for (cli = head; cli != last; cli = cli->next) {
			while (cli->next->dead) {
				struct httpclient *dead = cli->next;

				cli->next = dead->next;
				delete_httpclient(dead);
			}
		}

		for (cli = head->next; cli != last; cli = cli->next)
			handle_httpclient(cli);

		FD_ZERO(&fds);
		FD_SET(s, &fds);
		for (cli = head->next; cli != last; cli = cli->next) {
			int sock;

			sock = http_connection_fdset(cli->local, &fds);
			if (sock >= max)
				max = sock + 1;
			sock = http_connection_fdset(cli->remote, &fds);
			if (sock >= max)
				max = sock + 1;
		}
		tv.tv_sec = nr_httpclients ? 10 : 60; /* 10sec or 60sec */
		tv.tv_usec = 0;
		ret = select(max, &fds, NULL, NULL, &tv);
		if (ret == -1)
			break;
		if (ret == 0)
			continue;
		if (FD_ISSET(s, &fds)) {
			cli = accept_localhttp(s);
			/* insert */
			cli->next = head->next;
			head->next = cli;
		}
		/* update readable flags */
		for (cli = head->next; cli != last; cli = cli->next) {
			http_connection_fd_flag(cli->local, &fds);
			http_connection_fd_flag(cli->remote, &fds);
		}
	}
}

void usage(void)
{
	puts("Usage: ika <proxy host> <proxy port> [[bind addr:]bind port]");
	exit(1);
}

int main(int argc, char **argv)
{
	if (argc < 3)
		usage();

	if (lookup_addr_in(argv[1], argv[2], &proxyaddr) < 0) {
		printf("unknown proxy %s:%s\n", argv[1], argv[2]);
		exit(1);
	}

	bindaddr.sin_family = AF_INET;
	bindaddr.sin_addr.s_addr = INADDR_ANY;
	if (argc > 3) {
		char *p = strstr(argv[3], ":");

		if (p) {
			*p++ = '\0';
			bindaddr.sin_addr.s_addr = inet_addr(argv[3]);
		} else {
			p = argv[3];
		}

		bindport = strtoul(p, NULL, 0);
	}
	bindaddr.sin_port = htons(bindport);

	localhttp();

	return 0;
}
