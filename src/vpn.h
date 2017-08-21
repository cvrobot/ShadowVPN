/**
  vpn.h

  Copyright (C) 2015 clowwindy

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

#ifndef VPN_H
#define VPN_H

#include <time.h>

#include "args.h"
#include "nat.h"

#define REQ_TYPE_LOGIN 1
#define REQ_TYPE_LOGOUT 2
#define REQ_TYPE_CONTST 3
#define REQ_TYPE_EXIT 4

#define RSP_REQ_FAIL -1;
#define RSP_TOK_FAIL -2;
#define RSP_CON_FAIL -3;
#define RSP_ERR_REQ  -4;
#define RSP_TIME_OUT -5;

typedef struct {
  int type;//1:login,2:logout,3:exit
  union{
    char data[40];
    struct{
      char uid[10];
      char pwd[20];
      char token[SHADOWVPN_USERTOKEN_LEN];
      uint32_t client_ip;
    };
  };
  int rsp;//OK if it is same as type
}vpn_cmd_t;

typedef struct {
  int running;
  int nsock;
  int *socks;
  int conn_sock;
  int tun;
  /* select() in winsock doesn't support file handler */
#ifndef TARGET_WIN32
  int control_pipe[2];
#else
  int control_fd;
  struct sockaddr control_addr;
  socklen_t control_addrlen;
  struct sockaddr ctl_rmt_addr;
  socklen_t ctl_rmt_addrlen;
  HANDLE cleanEvent;
#endif
  unsigned char *tun_buf;
  unsigned char *udp_buf;
  unsigned char *conn_buf;

  /* the address we currently use (client only) */
  struct sockaddr_storage conn_addr;
  /* points to above, just for convenience */
  struct sockaddr *conn_addrp;
  socklen_t conn_addrlen;

  /* the address we currently use (client only) */
  struct sockaddr_storage remote_addr;
  /* points to above, just for convenience */
  struct sockaddr *remote_addrp;
  socklen_t remote_addrlen;
  shadowvpn_args_t *args;

  /* server with NAT enabled only */
  nat_ctx_t *nat_ctx;
} vpn_ctx_t;

/* return -1 on error. no need to destroy any resource */
int vpn_ctx_init(vpn_ctx_t *ctx, shadowvpn_args_t *args);

/* return -1 on error. no need to destroy any resource */
int vpn_run(vpn_ctx_t *ctx);

/* return -1 on error. no need to destroy any resource */
int vpn_stop(vpn_ctx_t *ctx);

/* these low level functions are exposed for Android jni */
#ifndef TARGET_WIN32
int vpn_tun_alloc(const char *dev);
#endif
int vpn_udp_alloc(int if_bind, const char *host, int port,
                  struct sockaddr *addr, socklen_t* addrlen);

#endif
