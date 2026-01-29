/*
 * mss - macOS Socket Statistics
 * Similar to Linux ss, using netstat + libproc on macOS.
 *
 * Copyright (c) 2026 Murat Kaan Tekeli
 */

#define _DARWIN_C_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <libproc.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/proc_info.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_SOCKETS 8192
#define MAX_PID_MAP 16384
#define MSS_LINE_MAX 512
#define PROC_NAME_LEN 64

typedef enum {
	PROTO_TCP4,
	PROTO_TCP6,
	PROTO_UDP4,
	PROTO_UDP6,
	PROTO_ANY
} proto_t;

typedef struct {
	proto_t proto;
	char local[64];
	char remote[64];
	char state[32];
} sock_entry_t;

typedef struct {
	int pid;
	char name[PROC_NAME_LEN];
} pid_info_t;

static int opt_tcp;
static int opt_udp;
static int opt_listen;
static int opt_numeric = 1;  /* default numeric on macOS */
static int opt_pid;
static int opt_help;

static sock_entry_t *sockets;
static size_t nsockets;
static size_t sockets_cap;

typedef struct { char key[96]; pid_info_t value; } pid_map_entry_t;
static pid_map_entry_t pid_map[MAX_PID_MAP];
static size_t pid_map_len;

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [options]\n"
		"  -t    TCP only\n"
		"  -u    UDP only\n"
		"  -l    Listening sockets only\n"
		"  -n    Numeric (no resolution) [default]\n"
		"  -p    Show PID/process (partial, requires privileges)\n"
		"  -h    Show this help\n",
		prog);
}

static proto_t parse_proto(const char *s)
{
	if (strncmp(s, "tcp4", 4) == 0) return PROTO_TCP4;
	if (strncmp(s, "tcp6", 4) == 0) return PROTO_TCP6;
	if (strncmp(s, "tcp46", 5) == 0) return PROTO_TCP4;  /* dual-stack */
	if (strncmp(s, "udp4", 4) == 0) return PROTO_UDP4;
	if (strncmp(s, "udp6", 4) == 0) return PROTO_UDP6;
	return PROTO_ANY;
}

static int is_tcp(proto_t p) { return p == PROTO_TCP4 || p == PROTO_TCP6; }
static int is_udp(proto_t p) { return p == PROTO_UDP4 || p == PROTO_UDP6; }
static int is_listen(const char *state) { return strcasecmp(state, "LISTEN") == 0; }

static int add_socket(proto_t proto, const char *local, const char *remote, const char *state)
{
	if (nsockets >= sockets_cap) {
		sockets_cap = sockets_cap ? sockets_cap * 2 : 256;
		sock_entry_t *n = realloc(sockets, sockets_cap * sizeof(sock_entry_t));
		if (!n) return -1;
		sockets = n;
	}
	sock_entry_t *e = &sockets[nsockets++];
	e->proto = proto;
	snprintf(e->local, sizeof(e->local), "%s", local);
	snprintf(e->remote, sizeof(e->remote), "%s", remote);
	snprintf(e->state, sizeof(e->state), "%s", state);
	return 0;
}

static int parse_netstat_line(char *line)
{
	char proto[8], local[64], remote[64], state[32];
	int n = sscanf(line, "%7s %*d %*d %63s %63s %31s",
		       proto, local, remote, state);
	if (n < 4) return 0;
	proto_t p = parse_proto(proto);
	if (p == PROTO_ANY) return 0;
	if (opt_tcp && !is_tcp(p)) return 0;
	if (opt_udp && !is_udp(p)) return 0;
	if (opt_listen && !is_listen(state)) return 0;
	return add_socket(p, local, remote, state) == 0;
}

static void run_netstat(void)
{
	FILE *fp = popen("netstat -an 2>/dev/null", "r");
	if (!fp) {
		perror("netstat");
		return;
	}
	char line[MSS_LINE_MAX];
	while (fgets(line, sizeof(line), fp)) {
		if (line[0] == 't' || line[0] == 'u')  /* tcp4/6, udp4/6 */
			parse_netstat_line(line);
	}
	pclose(fp);
}

static void make_pid_key(proto_t proto, const char *laddr, int lport, char *out, size_t outsz)
{
	const char *pstr = "?";
	if (proto == PROTO_TCP4 || proto == PROTO_TCP6) pstr = "tcp";
	else if (proto == PROTO_UDP4 || proto == PROTO_UDP6) pstr = "udp";
	snprintf(out, outsz, "%s:%s:%d", pstr, laddr, lport);
}

static void pid_map_add(const char *key, int pid, const char *name)
{
	if (pid_map_len >= MAX_PID_MAP) return;
	pid_map_entry_t *e = &pid_map[pid_map_len];
	strncpy(e->key, key, sizeof(e->key) - 1);
	e->key[sizeof(e->key) - 1] = '\0';
	e->value.pid = pid;
	strncpy(e->value.name, name, PROC_NAME_LEN - 1);
	e->value.name[PROC_NAME_LEN - 1] = '\0';
	pid_map_len++;
}

static pid_info_t *pid_map_lookup(const char *key)
{
	for (size_t i = 0; i < pid_map_len; i++)
		if (strcmp(pid_map[i].key, key) == 0)
			return &pid_map[i].value;
	return NULL;
}

static void build_pid_map(void)
{
	char name[256];
	pid_t pids[2048];
	int n = proc_listallpids(pids, sizeof(pids));
	if (n <= 0) return;
	int num_pids = n / sizeof(pid_t);

	for (int i = 0; i < num_pids; i++) {
		pid_t pid = pids[i];
		if (pid <= 0) continue;
		if (proc_name(pid, name, (uint32_t)sizeof(name)) <= 0)
			name[0] = '\0';

		struct proc_fdinfo *fds = malloc(PROC_PIDLISTFD_SIZE * 256);
		if (!fds) continue;
		int fd_count = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, PROC_PIDLISTFD_SIZE * 256);
		if (fd_count <= 0) { free(fds); continue; }
		int nfds = fd_count / (int)PROC_PIDLISTFD_SIZE;

		for (int j = 0; j < nfds; j++) {
			if (fds[j].proc_fdtype != PROX_FDTYPE_SOCKET) continue;
			struct socket_fdinfo si;
			int ret = proc_pidfdinfo(pid, fds[j].proc_fd, PROC_PIDFDSOCKETINFO, &si, sizeof(si));
			if (ret != sizeof(si)) continue;

			int kind = si.psi.soi_kind;
			if (kind != SOCKINFO_TCP && kind != SOCKINFO_IN) continue;

			int lport = 0;
			char laddr[64] = "*";
			if (kind == SOCKINFO_TCP) {
				lport = ntohs((uint16_t)si.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport);
				if (si.psi.soi_proto.pri_tcp.tcpsi_ini.insi_vflag == INI_IPV4) {
					struct in_addr a = si.psi.soi_proto.pri_tcp.tcpsi_ini.insi_laddr.ina_46.i46a_addr4;
					inet_ntop(AF_INET, &a, laddr, sizeof(laddr));
				} else {
					inet_ntop(AF_INET6, &si.psi.soi_proto.pri_tcp.tcpsi_ini.insi_laddr.ina_6, laddr, sizeof(laddr));
				}
				char key[96];
				make_pid_key(PROTO_TCP4, laddr, lport, key, sizeof(key));
				pid_map_add(key, pid, name);
			} else {
				lport = ntohs((uint16_t)si.psi.soi_proto.pri_in.insi_lport);
				if (si.psi.soi_proto.pri_in.insi_vflag == INI_IPV4) {
					struct in_addr a = si.psi.soi_proto.pri_in.insi_laddr.ina_46.i46a_addr4;
					inet_ntop(AF_INET, &a, laddr, sizeof(laddr));
				} else {
					inet_ntop(AF_INET6, &si.psi.soi_proto.pri_in.insi_laddr.ina_6, laddr, sizeof(laddr));
				}
				char key[96];
				make_pid_key(PROTO_UDP4, laddr, lport, key, sizeof(key));
				pid_map_add(key, pid, name);
			}
		}
		free(fds);
	}
}

/* Extract addr and port from netstat "addr.port" (last dot separates port). */
static void local_to_key(const char *local, proto_t proto, char *key, size_t keylen)
{
	char buf[64];
	const char *last_dot = strrchr(local, '.');
	if (!last_dot || last_dot == local) return;
	size_t addr_len = (size_t)(last_dot - local);
	if (addr_len >= sizeof(buf)) return;
	memcpy(buf, local, addr_len);
	buf[addr_len] = '\0';
	int port = atoi(last_dot + 1);
	make_pid_key(proto, buf, port, key, keylen);
}

static void print_sockets(void)
{
	if (opt_pid && pid_map_len == 0)
		build_pid_map();

	printf("%-6s %-22s %-22s %-12s", "Proto", "Local", "Foreign", "State");
	if (opt_pid) printf(" %-8s %s", "PID", "Process");
	printf("\n");

	for (size_t i = 0; i < nsockets; i++) {
		sock_entry_t *e = &sockets[i];
		const char *proto = "???";
		if (e->proto == PROTO_TCP4) proto = "tcp";
		else if (e->proto == PROTO_TCP6) proto = "tcp6";
		else if (e->proto == PROTO_UDP4) proto = "udp";
		else if (e->proto == PROTO_UDP6) proto = "udp6";

		printf("%-6s %-22s %-22s %-12s", proto, e->local, e->remote, e->state);
		if (opt_pid) {
			char key[96];
			local_to_key(e->local, e->proto, key, sizeof(key));
			pid_info_t *pi = pid_map_lookup(key);
			if (pi)
				printf(" %-8d %s", pi->pid, pi->name);
			else
				printf(" %-8s %s", "-", "-");
		}
		printf("\n");
	}
}

int main(int argc, char **argv)
{
	int c;
	while ((c = getopt(argc, argv, "tulnph")) != -1) {
		switch (c) {
		case 't': opt_tcp = 1; break;
		case 'u': opt_udp = 1; break;
		case 'l': opt_listen = 1; break;
		case 'n': opt_numeric = 1; break;
		case 'p': opt_pid = 1; break;
		case 'h': opt_help = 1; break;
		default:
			usage(argv[0]);
			return 1;
		}
	}
	if (opt_help) {
		usage(argv[0]);
		return 0;
	}

	run_netstat();
	print_sockets();
	free(sockets);
	return 0;
}
