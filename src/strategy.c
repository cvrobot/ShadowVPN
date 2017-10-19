/**
  strategy.c

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

#include "shadowvpn.h"

#include <sys/types.h>
#include <unistd.h>
#include <time.h>

#ifndef TARGET_WIN32
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <sodium.h>

#define ADDR_TIMEOUT 30

int strategy_choose_socket(vpn_ctx_t *ctx)
{
  // rule: just pick a random socket
  if (ctx->nsock == 1) {
    return ctx->socks[0];
  }
  uint32_t r = randombytes_uniform(ctx->nsock);
  return ctx->socks[r];
}

static inline void save_addr(addr_info_t *addr_info, struct sockaddr *addrp,
                             socklen_t addrlen, time_t now) {
  memcpy(&addr_info->addr, addrp, addrlen);
  addr_info->addrlen = addrlen;
  addr_info->last_recv_time = now;
}

static inline void load_addr(addr_info_t *addr_info,
                             struct sockaddr *addr,
                             socklen_t *addrlen) {
  memcpy(addr, &addr_info->addr, addr_info->addrlen);
  *addrlen = addr_info->addrlen;
}

int strategy_choose_remote_addr(cli_info_t *cli, struct sockaddr *remote_addrp, socklen_t *remote_addrlen)
{
  // rules:
  // 1. if there isn't any address received from within ADDR_TIMEOUT
  //    choose latest
  // 2. if there are some addresses received from within ADDR_TIMEOUT
  //    choose randomly from them
  //
  // how we do this efficiently
  // 1. scan once and find latest, total number of not timed out addresses
  // 2. if number <= 1, use latest
  // 3. if number > 1, generate random i in (0, number),
  //    scan again and pick (i)th address not timed out
  int i, total_not_timed_out = 0, chosen;
  time_t now;
  addr_info_t *latest = NULL, *temp;

  if (cli->nknown_addr == 0) {
    return 0;
  }

  time(&now);

  for (i = 0; i < cli->nknown_addr; i++) {
    temp = &cli->known_addrs[i];
    if (latest == NULL ||
        latest->last_recv_time < temp->last_recv_time) {
      latest = temp;
    }
    if (now - temp->last_recv_time <= ADDR_TIMEOUT) {
      total_not_timed_out++;
    }
  }
  if (total_not_timed_out <= 1) {
    load_addr(latest, remote_addrp, remote_addrlen);
  } else {
    chosen = randombytes_uniform(total_not_timed_out);
    total_not_timed_out = 0;
    for (i = 0; i < cli->nknown_addr; i++) {
      temp = &cli->known_addrs[i];
      if (now - temp->last_recv_time <= ADDR_TIMEOUT) {
        if (total_not_timed_out == chosen) {
          load_addr(temp, remote_addrp, remote_addrlen);
          break;
        }
        total_not_timed_out++;
      }
    }
  }
  return 0;
}

void strategy_update_remote_addr_list(cli_info_t *cli, struct sockaddr *remote_addrp, socklen_t remote_addrlen)
{
  int i;
  time_t now;

  time(&now);

  // if already in list, update time and return
  for (i = 0; i < cli->nknown_addr; i++) {
    if (remote_addrlen == cli->known_addrs[i].addrlen) {
      if (0 == memcmp(remote_addrp, &cli->known_addrs[i].addr,
                      remote_addrlen)) {
        cli->known_addrs[i].last_recv_time = now;
        return;
      }
    }
  }
  // if address list is not full, just append remote addr
  if (cli->nknown_addr < cli->ctx->concurrency) {
    save_addr(&cli->known_addrs[cli->nknown_addr], remote_addrp,
              remote_addrlen, now);
    cli->nknown_addr++;
    return;
  }
  // if full, replace the oldest
  addr_info_t *oldest_addr_info = NULL;
  for (i = 0; i < cli->nknown_addr; i++) {
    if (oldest_addr_info == NULL ||
        oldest_addr_info->last_recv_time >
          cli->known_addrs[i].last_recv_time) {
      oldest_addr_info = &cli->known_addrs[i];
    }
  }
  if (oldest_addr_info) {
    save_addr(oldest_addr_info, remote_addrp, remote_addrlen, now);
  }
}

