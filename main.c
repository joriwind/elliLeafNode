
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
/*#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>*/



#define PORT 5683
#define BUFSZ 128
#define SERVER_PORT  (0xFF01)

int certificates = 1;
int shutdown = 0;

int sock_snd, sock_rcv, if_id;
sockaddr6_t sa_rcv, sa_snd;

uint8_t scratch_raw[BUFSZ];
coap_rw_buffer_t scratch_buf = {scratch_raw, sizeof(scratch_raw)};
static coap_endpoint_path_t path = {1, {"node"}};


/**
 * Function not yet used!
**/
word32 rand_gen2(void){
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
 * Do not use this function, it return 0: sysconfig.id is not declared!
**/
static uint16_t get_hw_addr(void)
{
   printf("Sysconfig hardware address: %i\n", sysconfig.id);
    return sysconfig.id;
}

void udpif_get_ipv6_address(ipv6_addr_t *addr, uint16_t local_addr)
{
    ipv6_addr_init(addr, 0xfe80, 0x0, 0x0, 0x0, 0x0, 0x00ff, 0xfe00, local_addr);
}

/* init transport layer & routing stuff*/
static void _init_tlayer(void)
{
   if(net_if_set_hardware_address(0, 1) == 0){
      printf("Unable to set hardware address\n");
   }
    net_if_set_src_address_mode(0, NET_IF_TRANS_ADDR_M_SHORT);
    printf("set hawddr to: %d\n", net_if_get_hardware_address(0));

    //printf("initializing 6LoWPAN...\n");

    //sixlowpan_lowpan_init_interface(if_id);
}


void printTest(char *str) {
    printf("%s\n",str);
}

#ifdef CUSTOM_IO
   /**
    * CUSTOM_IO Receive function
   **/
   int CbIORecv(WOLFSSL* ssl, char* buf, int sz, void* ctx){
      int recvd;
      (void)ssl;
      (void)ctx;
      
      socklen_t len = sizeof(sa_rcv);
      
      //wolfSSL_dtls_get_peer(ssl, &sa, &sizeof(sa));
      recvd = socket_base_recvfrom(sock_rcv, buf, sz, 0, &sa_rcv, &len); //removed ssl->rflags
      
      if (recvd < 0) {
        printf("Error in CbIORecv: %i\n", recvd);
      }
      else if (recvd == 0) {
        
        printf("Error in CbIORecv: %i Connection closed\n", recvd);
      }

       return recvd;
   }

   /**
    * CUSTOM_IO Send function
   **/
   int CbIOSend(WOLFSSL* ssl, char* buf, int sz, void* ctx){
      //WOLFSSL_DTLS_CTX* dtlsCtx = (WOLFSSL_DTLS_CTX*)ctx;
      (void)ssl;
      (void)ctx;
      int send;
      int len = sz;
      
      send = (int)socket_base_sendto(sock_snd, &buf[sz - len], sz, 0, &sa_snd, sizeof(sa_snd)); //removed ssl->wflags
      
      if (send < 0) {
           printf("Error in CbIOSend: %i\n", send);
      }else if(send > sz){
         return sz;
      }
      if (send != sz){
         printf("Error send %i bytes and data was %i bytes!\n", send, sz);
      }
      
      return send;
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
   return 0;
}

void fill_nc(void)
{
   int numne = 2;
   int numig = 4;
   uint16_t neighbors[] = {33, 41};
   uint16_t ignore[] = {23, 31, 32, 51};

   ipv6_addr_t r_addr;
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
}

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
      wolfSSL_SetIORecv(ctx, CbIORecv);
      wolfSSL_SetIOSend(ctx, CbIOSend);
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
    }
    	printf("Get new ssl object\n");
      
   /* CUSTOM io or not?*/
   #ifdef CUSTOM_IO
      
      /** Sockets **/
      printf("initializing receive socket...\n");
      ipv6_addr_t r_addr;
      uint16_t l_addr;
      int address = 1;
      //ipv6_addr_init(&r_addr, 0xfe80, 0x0, 0x0, 0x0, 0x0, 0x00ff, 0xfe00, 1);
      //ipv6_addr_init(&r_addr, 0xabcd, 0x0, 0x0, 0x0, 0x0, 0x00ff, 0xfe00, (uint16_t)address);
      //ipv6_addr_init(&r_addr, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, (uint16_t)address);
      //ipv6_addr_init(&r_addr, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, (uint16_t)0);
      //ipv6_addr_set_all_routers_addr(&r_addr);
      l_addr = HTONS(1);
      ndp_neighbor_cache_add(0, &r_addr, &l_addr, 1, 0, NDP_NCE_STATUS_REACHABLE,
                           NDP_NCE_TYPE_TENTATIVE, 0xffff);
      
      
      sa_snd = (sockaddr6_t) { .sin6_family = AF_INET6,
               .sin6_port = HTONS(SERVER_PORT) };
      inet_pton(AF_INET6, "::1", &sa_snd.sin6_addr);
      
      memset(&sa_rcv, 0, sizeof(sa_rcv));
      sa_rcv.sin6_family = AF_INET6;
      sa_rcv.sin6_port = HTONS(SERVER_PORT);

      /*    
      if (inet_pton(AF_INET6, "::1", &sa_rcv.sin6_addr) < 1) {
         printf("Error and/or invalid IP address");
         return 1;
      }*/
            
      sock_snd = socket_base_socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
      sock_rcv = socket_base_socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
      
      if(sock_snd == -1){
         printf("Error creating send socket!");
         
      }else{
         
         /* Sending message to all that I am available for communication! */
         char buf[128];
         int rsplen = sizeof(buf);
         printf("Sending multicast to everyone to let know I exist!");
         if (0 == coap_ext_build_PUT(buf, &rsplen, "", &path)) {
            socket_base_sendto(sock_snd, buf, rsplen, 0, &sa_snd, sizeof(sa_snd));
            printf("[main-posix] PUT with payload %s sent to %s:%i\n", buf, "::1", sa_snd.sin6_port);
         }
         
      }
      //Check if bind succeeds
      if (-1 == socket_base_bind(sock_rcv, &sa_rcv, sizeof(sa_rcv))) {
         printf("Error: bind to receive socket failed!\n");
         socket_base_close(sock_rcv);
      }
      

      printf("Ready to receive requests.\n");
      
      /** client socket **/
      
      wolfSSL_set_fd(ssl, sock_rcv);
      
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
      if ((err = inet_pton(AF_INET6, "::1", &servAddr.sin6_addr)) != 1) {
         printf("Error and/or invalid IP address, %i \n", err);
         perror("inet_pton");
         exit(EXIT_FAILURE);
         return 1;
      }
      
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
      int n, rc;
      socklen_t len = sizeof(sa_rcv);
      char buf[128];
      //coap_packet_t pkt;
      printf("Trying to receive something\n");
      //n = socket_base_recvfrom(sock_rcv, buf, sizeof(buf), 0, &sa_rcv, &len);
      //if(n<=0){
      //   printf("Something went wrong with recvfrom\n");
      //}else{
      //   printf("Got %i bytes\n", n);
      //}
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
      socket_base_close(sock_rcv);
      socket_base_close(sock_snd);
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
   while (!shutdown) {
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
