#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
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

struct addr_entry {
	struct addr_entry *next;
	time_t lifetime;
	int type;
	char host[256]; /* host name, max 255 */
	uint32_t addr;
};

struct addr_entry *new_addr_entry(const char *host, uint32_t addr)
{
	struct addr_entry *p;

	if (strlen(host) >= 256)
		return NULL;

	p = malloc(sizeof(*p));
	memset(p, 0, sizeof(*p));
	p->lifetime = now + 600; /* 10min */
	strcpy(p->host, host);
	p->addr = addr;

	return p;
}

void delete_addr_entry(struct addr_entry *p)
{
	free(p);
}

static struct addr_entry a_head, a_last;

void init_addr_entries(void)
{
	a_head.next = &a_last;
	a_last.next = NULL;
}

void manage_addr_entries(void)
{
	struct addr_entry *p;

	for (p = &a_head; p != &a_last; p = p->next) {
		while (p->next->lifetime > 0 && p->next->lifetime < now) {
			struct addr_entry *dead = p->next;

			p->next = dead->next;
			delete_addr_entry(dead);
		}
	}
}

int get_addr(const char *host)
{
	struct sockaddr_in addr;
	struct addr_entry *p;

	for (p = a_head.next; p != &a_last; p = p->next) {
		if (!strcmp(p->host, host))
			return p->addr;
	}

	if (lookup_addr_in(host, NULL, &addr) == -1)
		return 0;

	p = new_addr_entry(host, addr.sin_addr.s_addr);
	if (!p)
		return 0;

	/* insert */
	p->next = a_head.next;
	a_head.next = p;

	return p->addr;
}

/* explicit list */
struct addr_entry elist_head, elist_last;

void init_explicit_list(void)
{
	elist_head.next = &elist_last;
	elist_last.next = NULL;

	FILE *fp = fopen("explicit.txt", "r");

	if (!fp)
		return;

	char buf[256];

	while (fgets(buf, 256, fp)) {
		struct addr_entry *p;
		char *lf;

		lf = strstr(buf, "\r\n");
		if (!lf)
			lf = strstr(buf, "\r");
		if (!lf)
			lf = strstr(buf, "\n");
		if (lf)
			*lf = '\0';

		if (buf[0] == '*') {
			p = new_addr_entry(&buf[1], 0);
			p->type = 1;
		} else {
			p = new_addr_entry(buf, 0);
			p->type = 0;
		}

		p->next = elist_head.next;
		elist_head.next = p;
	}

	fclose(fp);
}

int check_explicit_list(const char *host)
{
	struct addr_entry *p;

	for (p = elist_head.next; p != &elist_last; p = p->next) {
		if (p->type == 0) {
			if (!strcmp(p->host, host))
				return 1;
		} else {
			if (strstr(host, p->host))
				return 1;
		}
	}

	return 0;
}

struct http_connection {
	int sock;
	int close;
	int rflag;
	time_t last;
	char rbuf[BUFSZ];
	int rlen;
	int readptr;
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

	rlen = recv(conn->sock, conn->rbuf + curr, rest, MSG_DONTWAIT);
	if (rlen == -1 && errno == EAGAIN)
		return conn->rlen;
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
	conn->readptr = 0;
}

static int http_connection_readline(struct http_connection *conn,
				    char *buf, int maxlen)
{
	char *ptr = &conn->rbuf[conn->readptr];
	int n, rest;

	if (conn->rlen < 2)
		return -1;

	//printf("rest:%s", ptr);
	rest = conn->rlen - conn->readptr;
	if (maxlen > rest)
		maxlen = rest;
	for (n = 0; n < maxlen; n++) {
		if (ptr[n] == '\r' && ptr[n + 1] == '\n') {
			buf[n] = '\0';
			conn->readptr += n + 2;
			return n;
		}
		buf[n] = ptr[n];
	}

	return -2;
}

static int http_connection_send(struct http_connection *conn,
				char *buf, int len)
{
	if (conn->sock < 0)
		return -1;

	conn->last = now;

	return send(conn->sock, buf, len, 0);
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
	/* parse header */
	char *hdrs[256];
	int nr_hdrs;
	int parsedone;
	char requestline[1024];
	char *method, *scheme, *host, *port, *path, *proto;
	int contentlen;
	int bodyptr;
};

enum {
	HCLI_ST_INIT = 0,
	HCLI_ST_CONNECTING = 1,
	HCLI_ST_CONNECTED = 2,
	HCLI_ST_PASSTHROUGH = 3,
};

static void httpclient_reset_request(struct httpclient *cli)
{
	int i;

	for (i = 0; i < cli->nr_hdrs; i++) {
		free(cli->hdrs[i]);
		cli->hdrs[i] = NULL;
	}
	cli->nr_hdrs = 0;
	cli->contentlen = 0;
	cli->parsedone = 0;
}

static int handle_httpclient_local_request_parse(struct httpclient *cli)
{
	char *src, *dst;
	int i;

	/* get info from request header */
	cli->method = cli->requestline;
	dst = cli->method;
	src = cli->hdrs[0];
	/* get method */
	while (*src) {
		if (*src == ' ') {
			*dst++ = '\0';
			src++;
			goto get_scheme;
		}
		*dst++ = *src++;
	}
	return -1;

get_scheme:
	/* get scheme */
	cli->scheme = NULL;
	if (!strncmp(cli->method, "CONNECT", 7))
		goto get_host;
	cli->scheme = dst;
	while (*src) {
		if (*src == ':') {
			*dst++ = '\0';
			src += 3; /* http:// */
			goto get_host;
		}
		*dst++ = *src++;
	}
	return -1;

get_host:
	cli->host = dst;
	while (*src) {
		if (*src == ':') {
			*dst++ = '\0';
			src++;
			goto get_port;
		}
		if (*src == '/') {
			*dst++ = '\0';
			src++;
			cli->port = NULL;
			goto get_path;
		}
		if (*src == ' ') {
			*dst++ = '\0';
			src++;
			cli->port = NULL;
			cli->path = NULL;
			goto get_proto;
		}
		*dst++ = *src++;
	}
	return -1;

get_port:
	cli->port = dst;
	while (*src) {
		if (*src == '/') {
			*dst++ = '\0';
			src++;
			goto get_path;
		}
		if (*src == ' ') {
			*dst++ = '\0';
			src++;
			cli->path = NULL;
			goto get_proto;
		}
		*dst++ = *src++;
	}
	return -1;

get_path:
	cli->path = dst;
	while (*src) {
		if (*src == ' ') {
			*dst++ = '\0';
			src++;
			goto get_proto;
		}
		*dst++ = *src++;
	}
	return -1;

get_proto:
	cli->proto = dst;
	while (*src)
		*dst++ = *src++;
	*dst++ = '\0';

	printf("<%u> %s %s %s %s %s %s\n",
		cli->id,
		cli->method, cli->scheme, cli->host,
		cli->port, cli->path, cli->proto);

	/* header process */
	for (i = 1; i < cli->nr_hdrs; i++) {
		char *hdr = cli->hdrs[i];

		puts(hdr);
		if (!strncmp(hdr, "Content-Length:", 15)) {
			cli->contentlen = strtoul(hdr + 15, NULL, 10);
			printf("<%u> data %u bytes\n",
			       cli->id, cli->contentlen);
		}
	}

	return 0;
}

static void handle_httpclient_local_connect(struct httpclient *cli)
{
	struct http_connection *conn = cli->local;

	while (!cli->parsedone) {
		char buf[1024];
		int ret;

		ret = http_connection_readline(conn, buf, 1024);
		if (ret == -1)
			return;
		if (ret == -2) {
			/* unable to handle this request */
			http_connection_close(conn);
			return;
		}
		if (ret < 0)
			return;
		if (ret == 0) {
			cli->parsedone = 1;
			break;
		}
		cli->hdrs[cli->nr_hdrs] = strdup(buf);
		cli->nr_hdrs++;
	}

	if (handle_httpclient_local_request_parse(cli) == -1) {
		printf("<%u> parse request failed\n", cli->id);
		http_connection_close(conn);
		return;
	}

	if (!check_explicit_list(cli->host)) {
		int clen = cli->local->rlen - cli->local->readptr;

		cli->contentlen -= clen;
		http_connection_send(cli->remote, cli->local->rbuf, cli->local->rlen);
		http_connection_bufclear(cli->local);
		if (cli->contentlen > 0) {
			cli->status = HCLI_ST_PASSTHROUGH;
			return;
		}

		printf("<%u> request for %s done\n", cli->id, cli->host);
		if (strncmp(cli->method, "CONNECT", 7))
			cli->status = HCLI_ST_INIT;
		else
			cli->status = HCLI_ST_CONNECTED;
		httpclient_reset_request(cli);
		return;
	}

	uint32_t ii = get_addr(cli->host);

	if (ii == 0) {
		printf("<%u> lookup addr for %s error\n", cli->id, cli->host);
		return;
	}

	char connline[4096];
	char ip[64];

	sprintf(ip, "%u.%u.%u.%u",
		ii & 0xff,
		(ii >> 8) & 0xff,
		(ii >> 16) & 0xff,
		(ii >> 24) & 0xff);

	sprintf(connline, "CONNECT %s:%s HTTP/1.0\r\n\r\n",
		ip,
		cli->port ? cli->port : "80");
	printf("<%u> %s -> %s", cli->id, cli->host, connline);

	http_connection_send(cli->remote, connline, strlen(connline));
	if (!strncmp(cli->method, "CONNECT", 7)) {
		/* browser should handle after CONNECT */
		cli->status = HCLI_ST_CONNECTED;
		http_connection_bufclear(cli->local);
		return;
	}

	/* wait a CONNECT */
	cli->status = HCLI_ST_CONNECTING;

	cli->bodyptr = cli->local->readptr;
	if (cli->local->rlen <= cli->bodyptr) {
		http_connection_bufclear(cli->local);
		cli->bodyptr = 0;
	}
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
	case HCLI_ST_PASSTHROUGH:
		cli->contentlen -= cli->local->rlen;

		http_connection_send(cli->remote, cli->local->rbuf, cli->local->rlen);
		if (cli->contentlen <= 0) {
			printf("<%u> request for %s done\n", cli->id, cli->host);
			cli->status = HCLI_ST_INIT;
			httpclient_reset_request(cli);
		}
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

	char line[1024];

	sprintf(line,
		"%s /%s %s\r\n",
		cli->method,
		cli->path ? cli->path : "",
		cli->proto);

	http_connection_send(conn, line, strlen(line));

	for (int i = 1; i < cli->nr_hdrs; i++) {
		char *hdr = cli->hdrs[i];

		if (!strncmp(hdr, "Connection", 10))
			continue;
		if (!strncmp(hdr, "Proxy", 5))
			continue;
		http_connection_send(conn, hdr, strlen(hdr));
		http_connection_send(conn, "\r\n", 2);
	}

	char *connclose = "Connection: close\r\n\r\n";

	http_connection_send(conn, connclose, strlen(connclose));

	if (cli->bodyptr > 0) {
		http_connection_send(conn,
				     cli->local->rbuf + cli->bodyptr,
				     cli->local->rlen - cli->bodyptr);
	}

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
	printf("delete httpclient %u for %s\n", cli->id, cli->host);
	--nr_httpclients;

	int i;

	for (i = 0; i < 256; i++)
		free(cli->hdrs[i]);

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

	init_addr_entries();
	init_explicit_list();

	max = s + 1;
	for (;;) {
		struct timeval tv;
		int ret;
		struct httpclient *cli;

		now = time(NULL);

		manage_addr_entries();
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
