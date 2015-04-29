#include <stdio.h>

#include "byteorder.h"
#include "kernel.h"
#include "net/ng_pktbuf.h"
#include "net/ng_netreg.h"
#include "net/ng_pktdump.h"
#include "net/ng_pkt.h"
#include "net/ng_netbase.h"
#include "net/ng_udp.h"
#include "net/ng_ipv6.h"
#include "net/ng_netreg.h"

#include <wolfssl/ssl.h>

#define MSG_RETRANSMIT 0x4554
#define MSG_CHECKASYNC 0x7667


int udp_init(char* src_port);
int udp_recv(WOLFSSL* ssl, char* buf, int sz, void* ctx);
int wolfssl_udp_send(WOLFSSL* ssl, char* buf, int sz, void* ctx);
int udp_send(char* buf, int sz);
int set_udp_src_dst(ng_ipv6_addr_t* src_addr, ng_ipv6_addr_t* dst_addr, uint16_t* src_port, uint8_t* dst_port);