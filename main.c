
/**
 * @{
 *
 * @file
 * @brief       Coap server using UPD with DTLS security
 *
 * @author      Jori Winderickx
 *
 * @}
 */

#include <stdio.h>
#include <string.h>
#include "main.h"
#include "objects.h"

#define NOMAC_STACK_SIZE (KERNEL_CONF_STACKSIZE_DEFAULT)
/**
 * @brief   Stack for the nomac thread
 */
static char nomac_stack[NOMAC_STACK_SIZE];

#define MAC_PRIO                (PRIORITY_MAIN - 4)

#define PORT 5683
#define BUFSZ 1024
#define SERVER_PORT  (0xFF01)

int certificates = 1;
int shutdown_server = 0;

ng_ipv6_addr_t* srcAddress;

uint8_t scratch_raw[BUFSZ];
coap_rw_buffer_t scratch_buf = {scratch_raw, sizeof(scratch_raw)};
static coap_endpoint_path_t path = {1, {"node"}};

/**
 * @brief   Buffer size used by the shell
 */
#define SHELL_BUFSIZE           (64U)

typedef struct buffer_data {
    char* cipher_receive[BUFSZ];
    char* cipher_send[BUFSZ];
    char* clear_receive[BUFSZ];
    char* clear_send[BUFSZ];
} buffer_data;

buffer_data* buffers;


/**
 * Random number generator
**/
word32 rand_generator(void){
   return (word32)genrand_uint32();
}

#ifdef SHELL
   static int shell_readc(void)
   {
       char c = 0;
       (void) posix_read(uart0_handler_pid, &c, 1);
       return c;
   }

   static void shell_putchar(int c)
   {
       (void) putchar(c);
   }

   void hello_world(char *str) {
      (void) str;
       printf("hello world!\n");
   }
   const shell_command_t shell_commands[] = {
    //{"hello", "prints hello world", hello_world},
    { NULL, NULL, NULL }
   };
#endif
   
   /**
 * @Brief   Read chars from STDIO
 */
static int shell_read(void)
{
    return (int)getchar();
}

/**
 * @brief   Write chars to STDIO
 */
static void shell_put(int c)
{
    putchar((char)c);
}

/**
 * Do not use this function, it return 0: sysconfig.id is not declared!
**/
static uint16_t get_hw_addr(void)
{
   printf("Sysconfig hardware address: %i\n", sysconfig.id);
    return sysconfig.id;
}


/* init transport layer & routing stuff*/
static void _init_tlayer(void)
{
    

    int res;
    kernel_pid_t netif;
    size_t num_netif;
    
   //if(net_if_set_hardware_address(0, 1) == 0){
   //   printf("Unable to set hardware address\n");
   //}
   //net_if_set_src_address_mode(0, NET_IF_TRANS_ADDR_M_SHORT);
   //printf("Hardware address of node: %d\n", net_if_get_hardware_address(0));

   //printf("initializing 6LoWPAN...\n");
   
   /* initialize network module(s) */
    ng_netif_init();

    /* initialize IPv6 interfaces */
    ng_ipv6_netif_init();

    /* initialize netdev_eth layer */
    ng_netdev_eth_init(&ng_netdev_eth, (dev_eth_t *)&dev_eth_tap);
   
    /* start MAC layer */
    res = ng_nomac_init(nomac_stack, sizeof(nomac_stack), MAC_PRIO,
                        "eth_mac", (ng_netdev_t *)&ng_netdev_eth);
   
    /* initialize IPv6 addresses */
    netif = *(ng_netif_get(&num_netif));

    if (num_netif > 0) {

        printf("Found %i active interface\n", num_netif);
        ng_ipv6_netif_reset_addr(netif);
        res = init_ipv6_linklocal(netif, dev_eth_tap.addr);

        if (res < 0) {
            printf("link-local address initialization failed %i\n", res);
        }
        else {
            printf("Successfully initialized link-local adresses on first interface\n");
        }
        
        ng_ipv6_addr_t global_addr;
        ng_ipv6_addr_from_str(&global_addr, HOST_IP);
        res = ng_ipv6_netif_add_addr(netif, &global_addr, 64, 0);

        if (res < 0) {
            printf("Global address initialization failed %i\n", res);
        }
        
        char mac_buf[32];
        uint8_t remote_mac[6];
        ng_ipv6_addr_t remote_addr;
        /* Setup neighbour cache while NDP is unavailable */
        ng_ipv6_addr_from_str(&remote_addr, REMOTE_IP);

        memcpy(&mac_buf, REMOTE_MAC, 18);
        ng_netif_addr_from_str(&remote_mac[0],
                               6,
                               &mac_buf[0]);

        res = ng_ipv6_nc_add(netif, &remote_addr, &remote_mac[0], 6, 0);

        if (res < 0) {
            printf("setup of neighbour cache failed %i", res);
        }
    }else {
        printf("No active interfaces %i\n", num_netif);
    }
    
    
    udp_init("1");
    
   //sixlowpan_lowpan_init_interface(0);
   wolfSSL_SetRand_gen(rand_generator);
   
   
}


void printTest(char *str) {
    printf("%s\n",str);
}


/**
 * @brief   Setup a MAC-derived link-local, solicited-nodes and multicast address
 *          on IPv6 interface @p net_if.
 */
static int init_ipv6_linklocal(kernel_pid_t net_if, uint8_t *mac)
{
    char addr_buf[NG_IPV6_ADDR_MAX_STR_LEN];
    ng_ipv6_addr_t link_local, solicited, multicast;
    uint8_t eui64[8] = {0, 0, 0, 0xFF, 0xFE, 0, 0, 0};
    int res;

    /* Generate EUI-64 from MAC address */
    memcpy(&eui64[0], &mac[0], 3);
    memcpy(&eui64[5], &mac[3], 3);
    eui64[0] ^= 1 << 1;

    /* Generate link-local address from local prefix and EUI-64 */
    ng_ipv6_addr_set_link_local_prefix(&link_local);
    ng_ipv6_addr_set_aiid(&link_local, &eui64[0]);

    res = ng_ipv6_netif_add_addr(net_if,
                                 &link_local,
                                 64,
                                 false);

    if (res != 0) {
        return printf("setting link-local address failed %i\n", res);
    }
    else {
        printf("link-local address: %s\n",
              ng_ipv6_addr_to_str(&addr_buf[0],
                                  &link_local,
                                  NG_IPV6_ADDR_MAX_STR_LEN));
    }

    ng_ipv6_addr_set_solicited_nodes(&solicited, &link_local);

    res = ng_ipv6_netif_add_addr(net_if,
                                 &solicited,
                                 NG_IPV6_ADDR_BIT_LEN,
                                 false);

    if (res != 0) {
        return printf("setting solicited-nodes address failed %i\n", res);
    }
    else {
        printf("solicited-nodes address: %s\n",
              ng_ipv6_addr_to_str(&addr_buf[0],
                                  &solicited,
                                  NG_IPV6_ADDR_MAX_STR_LEN));
    }

    /* Setup multicast address */
    memcpy(&multicast, &link_local, sizeof(ng_ipv6_addr_t));

    ng_ipv6_addr_set_multicast(&multicast,
                               NG_IPV6_ADDR_MCAST_FLAG_TRANSIENT |   // No RP, temporary
                               NG_IPV6_ADDR_MCAST_FLAG_PREFIX_BASED, // unicast/prefix based
                               NG_IPV6_ADDR_MCAST_SCP_LINK_LOCAL);   // link-local scope

    res = ng_ipv6_netif_add_addr(net_if,
                                 &multicast,
                                 NG_IPV6_ADDR_BIT_LEN,
                                 false);

    if (res != 0) {
        printf("setting multicast address failed %i\n", res);
        return -1;
    }
    else {
        printf("multicast address: %s\n",
              ng_ipv6_addr_to_str(&addr_buf[0],
                                  &multicast,
                                  NG_IPV6_ADDR_MAX_STR_LEN));
    }

    return 0;
}


#ifdef CUSTOM_IO
   
   /**
    * CUSTOM_IO GenCookie function
   **/
   int CbIOGenCookie(WOLFSSL* ssl, byte *buf, int sz, void *ctx){
      uint8_t peerSz = sizeof(*srcAddress);
      byte digest[SHA_DIGEST_SIZE];
      int  ret = 0;
      
      (void)ssl;
      (void)ctx;
   
      ret = wc_ShaHash((byte*)srcAddress, peerSz, digest);
      if (ret != 0)
         return ret;

      if (sz > SHA_DIGEST_SIZE)
         sz = SHA_DIGEST_SIZE;
      XMEMCPY(buf, digest, sz);

      return sz;
   }
#endif


#ifdef NO_FILESYSTEM
   /**
    * Only when no filesystem is active with WOLFSSL library
   **/
   int readCertificate(WOLFSSL_CTX* ctx,char* certs){
      char buff[4048];
      char* buffer = buff;
      FILE *fp =fopen(certs, "r");
      if(fp == NULL){
         printf("Error reading file");
         return -1;
      }
      int rc = fgetc(fp);
      int i = 0;
      buffer[i] = rc;
      i++;
      while(!feof(fp)){
         rc = fgetc(fp);
         buffer[i] = rc;
         i++;
         if(i == 503){ //debug purposes
            i++;
         }
      }
      fclose(fp);
      
      return wolfSSL_CTX_load_verify_buffer(ctx, buffer,sizeof(buffer),"rb");
   }
#endif

/**
 * Thread
**/
void *second_thread(void *arg){
    (void) arg;
    //start_DTLS_Client();
    //printTest("Testing 2th thread");
    //populate_cache();
    
    newCoapClient();
    
    return NULL;
}



int main(void){
   /* start shell */
    
    shell_t shell;
   #ifdef SHELL
      posix_open(uart0_handler_pid, 0);
      shell_t shell;
   #endif
   printf("Staring coap server, searching for DTLS server\n");
   _init_tlayer();
    
   #ifdef CYASSL_DTLS
   printf("DTLS enabled(cya)\n");
   #endif
   #ifdef WOLFSSL_DTLS
   printf("DTLS enabled(wolf)\n");
   #endif
   
   printf("Sizeof stack: %i\n", sizeof(t2_stack));
   //printf("Length of stack: %i",t2_stack.size());
   
   thread_create(t2_stack, sizeof(t2_stack), PRIORITY_MAIN ,
                 CREATE_STACKTEST, second_thread, NULL, "dtls thread");
   
   
   #ifdef SHELL
      shell_init(&shell, shell_commands, UART0_BUFSIZE, shell_readc, shell_putchar);
      shell_run(&shell);
   #endif
/* start the shell */
    //shell_init(&shell, NULL, SHELL_BUFSIZE, shell_read, shell_put);
    //shell_run(&shell);
   return 0;
}

/*
void fill_nc(void)
{
   int numne = 2;
   int numig = 4;
   uint16_t neighbors[] = {33, 41};
   uint16_t ignore[] = {23, 31, 32, 51};

   ng_ipv6_addr_t r_addr;
   uint16_t l_addr;

   for (int i = 0; i < numne; i++) {
      printf("Adding %u as neighbor\n", neighbors[i]);
      udpif_get_ipv6_address(&r_addr, neighbors[i]);
      l_addr = HTONS(neighbors[i]);
      ndp_neighbor_cache_add(0, &r_addr, &l_addr, 2, 0,
                            NDP_NCE_STATUS_REACHABLE, 
                            NDP_NCE_TYPE_TENTATIVE, 
                            0xffff);
   }
   for (int i = 0; i < numig; i++) {
     printf("Ignoring %u\n", ignore[i]);
   }
}*/

void loadCertificates(WOLFSSL_CTX* ctx){
   if(certificates){
      if (wolfSSL_CTX_use_certificate_file(ctx, eccCert, SSL_FILETYPE_PEM)
                != SSL_SUCCESS)
         printf("can't load server cert file\n");

      if (wolfSSL_CTX_use_PrivateKey_file(ctx, eccKey, SSL_FILETYPE_PEM)
             != SSL_SUCCESS)
         printf("can't load server key file\n");
   }else{
      //TODO: PSK
   }
}


/**
 * Create new Client and setup connection:
 * Create socket, set up DTLS and do handshake with host.
**/
int newCoapClient(void){
   WOLFSSL* 	ssl = 0;
   WOLFSSL_CTX* ctx = 0;
   WOLFSSL_METHOD* method = 0;
   
   //char        cert_array[]  = "./certs/ca-cert.pem";
   //char        cert_array[]  = "./certs/server-ecc.pem";
   //char*       certs = cert_array;
   const char* cipherList = "ECDHE-ECDSA-AES128-CCM-8";
   int err;
      
   wolfSSL_Init();
   wolfSSL_Debugging_ON();
        
   //redefine allocators used by wolfSSL to allocators of RIOT
   err = wolfSSL_SetAllocators(malloc,free,realloc);
   if(err < 0){
      printf("Unable to set allocators wolfSSL \n");
      return -1;
   }
   //Set method to DTLSv1_2 Client
   method = wolfDTLSv1_2_server_method();
   
   //Create CTX
   if ( (ctx = wolfSSL_CTX_new(method)) == NULL) {
      fprintf(stderr, "CyaSSL_CTX_new error.\n");
      return 1;
   }
   
   //Load certificates
   #ifndef NO_FILESYSTEM
      loadCertificates(ctx);
      
   #else
      if(readCertificate(ctx, certs) == -1){
         return 1;
      }
   #endif
    
    
   #ifdef CUSTOM_IO
      //Redefine I/O of wolfSSL
      wolfSSL_SetIORecv(ctx, udp_recv);
      wolfSSL_SetIOSend(ctx, wolfssl_udp_send);
      wolfSSL_CTX_SetGenCookie(ctx, CbIOGenCookie);
   #endif
   
   //set cipher list
   if( wolfSSL_CTX_set_cipher_list(ctx,cipherList ) != SSL_SUCCESS){
      fprintf(stderr, "Error setting cipherList %s, please check library.\n", cipherList);
      return 1;
   }
    printf("Try get ssl object");
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
    	printf("unable to get ssl object\n");
        return 1;
    }else{
      #ifdef CUSTOM_IO
         wolfSSL_SetIOReadCtx(ssl, buffers);
         wolfSSL_SetIOWriteCtx(ssl, buffers);
      #endif
    	printf("Got new ssl object\n");
    }
      
   /* CUSTOM io or not?*/
   #ifdef CUSTOM_IO
      
      /** Sockets **/
      printf("initializing udp...\n");
      ng_ipv6_addr_t r_addr;
      ng_ipv6_addr_t s_addr;
      ng_ipv6_addr_mcast_scp_t scope = NG_IPV6_ADDR_MCAST_SCP_GLOBAL;
      
      ng_ipv6_addr_set_all_nodes_multicast(&r_addr, scope );
      
      ng_ipv6_addr_from_str(&r_addr, "::1");
      ng_ipv6_addr_from_str(&s_addr, "fddf:dead:beef::1" );
      
      uint8_t src_port = HTONS(1);
      uint8_t dst_port = HTONS(5683);
      set_udp_src_dst( &s_addr, &r_addr, &src_port, &dst_port);
      srcAddress = &s_addr;
         
      /* Sending message to all that I am available for communication! */
      char buf[128];
      int rsplen = sizeof(buf);
      printf("Sending multicast to everyone to let know I exist!\n");
      if (0 == coap_ext_build_PUT(buf, &rsplen, "", &path)) {
         if(udp_send(buf, rsplen) > 1){
            printf("[main-posix] PUT with payload sent to %s\n", "::1");
         }else{
            printf("Somthing went wrong with sending HELLO I AM CoAP SERVER!\n");
            return -1;
         }
      }
      
      printf("Ready to receive requests.\n");
      
   #else
      int sockfd = 0;
      int status;
      struct addrinfo sainfo, *psinfo;
      struct sockaddr_in6 servAddr;
      int sin6len;

      sin6len = sizeof(struct sockaddr_in6);
      
      sockfd = socket(PF_INET6, SOCK_DGRAM,0);

      memset(&servAddr, 0, sizeof(struct sockaddr_in6));
      servAddr.sin6_port = htons(SERV_PORT);
      servAddr.sin6_family = AF_INET6;
      //servAddr.sin6_addr = in6addr_any;
      ng_ipv6_addr_from_str(&sa_snd.sin6_addr, "::1");
      /*if ((err = inet_pton(AF_INET6, "::1", &servAddr.sin6_addr)) != 1) {
         printf("Error and/or invalid IP address, %i \n", err);
         perror("inet_pton");
         exit(EXIT_FAILURE);
         return 1;
      }*/
      
      status = bind(sockfd, (struct sockaddr *)&servAddr, sin6len);

      if(-1 == status)
        perror("bind"), exit(1);

      memset(&sainfo, 0, sizeof(struct addrinfo));
      memset(&servAddr, 0, sin6len);

      sainfo.ai_flags = 0;
      sainfo.ai_family = PF_INET6;
      sainfo.ai_socktype = SOCK_DGRAM;
      sainfo.ai_protocol = 0;
      status = getaddrinfo("::1", SERV_PORT, &sainfo, &psinfo);

      switch (status) 
      {
         case EAI_FAMILY: printf("family\n");
           break;
         case EAI_SOCKTYPE: printf("stype\n");
           break;
         case EAI_BADFLAGS: printf("flag\n");
           break;
         case EAI_NONAME: printf("noname\n");
           break;
         case EAI_SERVICE: printf("service\n");
           break;
      }
      char* buffer = "Test";
      
      status = sendto(sockfd, buffer, strlen(buffer), 0,
                     (struct sockaddr *)psinfo->ai_addr, sin6len);
      printf("buffer : %s \t%d\n", buffer, status);
      
      wolfSSL_set_fd(ssl, sockfd);
      //Set socket, does it do anything good?
   #endif
   
   int not_connected = 1;
   
   while(not_connected){
      
      printf("Trying to receive something\n");
      
      ssl = wolfSSL_new(ctx);
      if (wolfSSL_accept(ssl) != SSL_SUCCESS) {
         printf("SSL_accept failed\n");
         wolfSSL_free(ssl);
         //socket_base_close(clientfd);
         continue;
      }else{
         not_connected = 0;
         DatagramClient(ssl);
         
      }
   }

   wolfSSL_shutdown(ssl);
   wolfSSL_free(ssl);
   #ifdef CUSTOM_IO
   #else
      socket_close(sockfd);
   #endif
   wolfSSL_CTX_free(ctx);
   wolfSSL_Cleanup();

   return 0;
   
}


/* Send and receive function */
void DatagramClient (WOLFSSL* ssl) 
{
   char    buf[128];
   int     echoSz = 0;
   coap_packet_t pkt;
   int rc;
   while (!shutdown_server) {
      if((echoSz = wolfSSL_read(ssl, buf, sizeof(buf)-1)) > 0){
         if(echoSz > 0){
            printf("Received packet: ")
            coap_dump(buf, echoSz, true);
            printf("\n");
            
            if(0 != (rc = coap_parse(&pkt, buf, echoSz))){
               printf("Bad packet rc=%d\n", rc);
               
            }else{
               size_t rsplen = sizeof(buf);
               coap_packet_t rsppkt;
               printf("content:\n");
               coap_dumpPacket(&pkt);
               coap_handle_req(&scratch_buf, &pkt, &rsppkt);

               if (0 != (rc = coap_build(buf, &rsplen, &rsppkt)))
                   printf("coap_build failed rc=%d\n", rc);
               else
               {
                  printf("Sending packet: ");
                  coap_dump(buf, rsplen, true);
                  printf("\n");
                  printf("content:\n");
                  coap_dumpPacket(&rsppkt);
                  if(wolfSSL_write(ssl, buf, rsplen)){
                  printf("SSL_write failed\n");
                  }
               }
            }
         }
         printf("Packet processed\n");
         //TODO: the rest
 
      }
   }
}
