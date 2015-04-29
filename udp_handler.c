#include "udp_handler.h"
#include "net/ng_pktdump.h"

#define RCV_MSG_Q_SIZE      (64)
msg_t msg_q[RCV_MSG_Q_SIZE];
//Received message
msg_t msg;

ng_ipv6_addr_t* srcAddr;
ng_ipv6_addr_t* dstAddr;

uint16_t* srcPort;
uint8_t* dstPort;

static ng_netreg_entry_t _server = {NULL,
                                    NG_NETREG_DEMUX_CTX_ALL,
                                    KERNEL_PID_UNDEF};

int set_udp_src_dst(ng_ipv6_addr_t* src_addr, ng_ipv6_addr_t* dst_addr,
            uint16_t* src_port, uint8_t* dst_port){
   srcAddr = src_addr;
   dstAddr = dst_addr;
   srcPort = src_port;
   dstPort = dst_port;
   return 0;
}

int udp_init(char* src_port){
   //ng_netreg_entry_t me_reg;
   uint16_t port;
   /* register interest in all UDP packets on our port */
   port = ((uint16_t)atoi(src_port));
   if (port == 0) {
        printf("Error: invalid port specified\n");
        return -1;
    }
   _server.pid = ng_pktdump_getpid();
   _server.demux_ctx = (uint32_t)port;
   ng_netreg_register(NG_NETTYPE_UDP, &_server);
   
   //if(ng_netif_add(_server.pid) < 0){
   //    printf("Adding thread as interface faled\n");
   //    return -1;
   //}
   /* initialize message queue */
   msg_init_queue(msg_q, RCV_MSG_Q_SIZE);
   
   printf("Success: started UDP server on port %s\n", src_port);

   return 0;
}

/**
 * CUSTOM_IO Receive function
**/
int udp_recv(WOLFSSL* ssl, char* buf, int sz, void* ctx){
   int recvd;
   (void)ssl;
   (void)ctx;
   
   msg_receive(&msg);

   switch (msg.type) {
      case NG_NETAPI_MSG_TYPE_RCV:
         printf("Udp_handler: NG_NETAPI_MSG_TYPE_RCV\n");
         
         buf = msg.content.ptr;
         return sizeof(msg.content);
         //handle_message(ctx, ctx->endpoint, (coap_packet_t *)msg.content.ptr);
         break;

      case MSG_RETRANSMIT:
         printf("Udp_handler: MSG_RETRANSMIT NOT IMPLEMENTED\n");

         /* Loops over all pdus scheduled to send 
         while (nextpdu && nextpdu->t <= now - ctx->sendqueue_basetime) {
            retransmit(ctx, coap_pop_next(ctx));
         }*/

         break;

      case MSG_CHECKASYNC:
         /* DEBUG("MSG_CHECKASYNC not implemented\n"); 
         vtimer_set_msg(&check_notify, check_time,
                      sched_active_pid, MSG_CHECKASYNC, NULL);*/
         break;

      default:
         printf("Udp_handler: Received unidentified message\n");
         break;
   }
   
   printf("Error in Udp_handler: \n");
   
   return -1;
}

int wolfssl_udp_send(WOLFSSL* ssl, char* buf, int sz, void* ctx){
   (void)ssl;
   (void)ctx;
   return udp_send(buf, sz);
   
}

/**
 * CUSTOM_IO Send function
**/
int udp_send(char* buf, int sz){
   
   
   int len = sz;
   ng_pktsnip_t *payload, *udp, *ip;
   ng_netreg_entry_t *sendto;
   
   payload = ng_pktbuf_add(NULL, &buf[len - sz], sz,
                   NG_NETTYPE_UNDEF);

   udp = ng_udp_hdr_build(payload, NULL, 0,
                         (uint8_t *)&dstPort, 2);

   ip = ng_ipv6_hdr_build(udp, NULL, 0,
                         (uint8_t *)&dstAddr, sizeof(dstAddr));
   
   /* and forward packet to the network layer */
   sendto = ng_netreg_lookup(NG_NETTYPE_UDP, NG_NETREG_DEMUX_CTX_ALL);

   /* throw away packet if no one is interested */
   if (sendto == NULL) {
     printf("coap_network_send(): cannot send packet because network layer not found\n");
     ng_pktbuf_release(ip);
     return -1;
   }

   /* send packet to network layer */
   ng_pktbuf_hold(ip, ng_netreg_num(NG_NETTYPE_UDP, NG_NETREG_DEMUX_CTX_ALL) - 1);

   while (sendto != NULL) {
     ng_netapi_send(sendto->pid, ip);
     sendto = ng_netreg_getnext(sendto);
   }
   printf("Success: send %i byte\n", payload->size);

   return sz;
}