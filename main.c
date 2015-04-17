
/**
 * @{
 *
 * @file
 * @brief       Coap client using UPD with DTLS security
 *
 * @author      Jori Winderickx
 *
 * @}
 */

#include <stdio.h>
#include <string.h>
#include "main.h"
#include "objects.h"


#define PORT 5683
#define BUFSZ 128

#define RCV_MSG_Q_SIZE      (64)

msg_t msg_q[RCV_MSG_Q_SIZE];
static ipv6_addr_t prefix;
int sockfd, if_id;;
sockaddr6_t sa_rcv;


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

static uint16_t get_hw_addr(void)
{
    return sysconfig.id;
}

/* init transport layer & routing stuff*/
static void _init_tlayer(void)
{
    msg_init_queue(msg_q, RCV_MSG_Q_SIZE);

    net_if_set_hardware_address(0, get_hw_addr());
    DEBUG("set hawddr to: %d\n", get_hw_addr());

    printf("initializing 6LoWPAN...\n");

    ipv6_addr_init(&prefix, 0xABCD, 0xEF12, 0, 0, 0, 0, 0, 0);
    if_id = 0; /* having more than one interface isn't supported anyway */

    sixlowpan_lowpan_init_interface(if_id);
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
      int sd = *(int*)ctx;
      (void)ssl;
      /*
      socket_internal_t *socket;
      sockaddr6_t sa;
      socket = socket_base_get_socket(sd);
      socket_t *current_socket = &socket->socket_values;
      uint32_t saSz = sizeof(sa);
      sa = current_socket->local_address;
      //memset(&sa, 0, sizeof(sa));
      */
      
      socklen_t len = sizeof(sa_rcv);
      
      //wolfSSL_dtls_get_peer(ssl, &sa, &sizeof(sa));
      recvd = socket_base_recvfrom(sockfd, buf, sz, 0, &sa_rcv, &len); //removed ssl->rflags
      
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
      WOLFSSL_DTLS_CTX* dtlsCtx = (WOLFSSL_DTLS_CTX*)ctx;
      int sd = dtlsCtx->fd;
      int send;
      int len = sz;
      
      
      //Send data sizeof(buf)
      send = (int)socket_base_sendto(sockfd, &buf[sz - len], len, 0, &sa_rcv, sizeof(sa_rcv)); //removed ssl->wflags
      
      if (send < 0) {
           printf("Error in CbIOSend: %i\n", send);
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
void *second_thread(void *arg)
{
    (void) arg;
    //start_DTLS_Client();
    //printTest("Testing 2th thread");
    //populate_cache();
    
    newCoapClient();
    
    return NULL;
}



int main(void)
{
   /* start shell */
   #ifdef SHELL
      posix_open(uart0_handler_pid, 0);
      shell_t shell;
   #endif
   _init_tlayer();
    
   #ifdef CYASSL_DTLS
   printf("DTLS enabled(cya)\n");
   #endif
   #ifdef WOLFSSL_DTLS
   printf("DTLS enabled(wolf)\n");
   #endif
   
   //sixlowpan_lowpan_init_interface(id);
   printf("Sizeof stack: %i\n", sizeof(t2_stack));
   //printf("Length of stack: %i",t2_stack.size());
   kernel_pid_t monitor_pid = thread_create(t2_stack, sizeof(t2_stack), PRIORITY_MAIN ,
                 CREATE_STACKTEST, second_thread, NULL, "helper thread");
   
   //ipv6_register_packet_handler(monitor_pid);
   (void) puts("Welcome to RIOT!");
   #ifdef SHELL
      shell_init(&shell, shell_commands, UART0_BUFSIZE, shell_readc, shell_putchar);
      shell_run(&shell);
   #endif
   return 0;
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
   char        cert_array[]  = "./certs/server-ecc.pem";
   char*       certs = cert_array;
   const char* cipherList = "ECDHE-ECDSA-AES128-CCM-8";
   int err;
      
   wolfSSL_Init();
   wolfSSL_Debugging_ON();
        
   //redefine allocators used by wolfSSL to allocators of RIOT
   err = wolfSSL_SetAllocators(malloc,free,realloc);
   //Set method to DTLSv1_2 Client
   method = wolfDTLSv1_2_client_method();
   
   //Create CTX
   if ( (ctx = wolfSSL_CTX_new(method)) == NULL) {
      fprintf(stderr, "CyaSSL_CTX_new error.\n");
      return 1;
   }
   
   //Load certificates
   #ifndef NO_FILESYSTEM
      if ((err = wolfSSL_CTX_load_verify_locations(ctx, certs, 0) )
       != SSL_SUCCESS) {
         fprintf(stderr, "Error in load certificat %i\n", err);
         fprintf(stderr, "Error loading %s, please check the file.\n", certs);
         return 1;
      }
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
      /*
      int     	sockfd = 0;
      sockaddr6_t servAddr;
      
      memset(&servAddr, 0, sizeof(servAddr));
      servAddr.sin6_family = AF_INET;
      servAddr.sin6_port = HTONS(SERV_PORT);
      if (inet_pton(AF_INET6, "::1", &servAddr.sin6_addr) != 1) {
        printf("Error and/or invalid IP address");
        return 1;
      }
      printf("Got new socket object\n");

      wolfSSL_dtls_set_peer(ssl, &servAddr, sizeof(servAddr));

      //if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
      if ( (sockfd = socket_base_socket(PF_INET6, SOCK_DGRAM, 0)) < 0) {       
         printf("cannot create a socket.\n"); 
         return 1;
      }

      if (-1 == socket_base_bind(sockfd, &servAddr, sizeof(servAddr))) {
         printf("Error bind failed!\n");
         socket_base_close(sockfd);
         return NULL;
      }*/
      
      //According to mirocoap application:
      printf("initializing receive socket...\n");
      
      
      sa_rcv = (sockaddr6_t) { .sin6_family = AF_INET6,
               .sin6_port = HTONS(PORT) };

      sockfd = socket_base_socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);

      if (-1 == socket_base_bind(sockfd, &sa_rcv, sizeof(sa_rcv))) {
         printf("Error: bind to receive socket failed!\n");
         socket_base_close(sockfd);
      }

      printf("Ready to receive requests.\n");
      
      //Set socket, does it do anything good?
      wolfSSL_set_fd(ssl, sockfd);
      
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
      
    
    if (wolfSSL_connect(ssl) != SSL_SUCCESS) {
	    int err1 = wolfSSL_get_error(ssl, 0);
	    printf("err = %d, %s\n", err1, wolfSSL_ERR_reason_error_string(err1));
	    printf("SSL_connect failed");
        return 1;
    }
 
    DatagramClient(ssl);

    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    socket_base_close(sockfd);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();

    return 0;
   
}


/* Send and receive function */
void DatagramClient (WOLFSSL* ssl) 
{
    int  n = 0;
    char sendLine[MAXLINE], recvLine[MAXLINE - 1];

    while ((unsigned)fgets(sendLine, MAXLINE, stdin) != NULL) {
    
       if ( ( wolfSSL_write(ssl, sendLine, strlen(sendLine))) != 
	      strlen(sendLine)) {
            printf("SSL_write failed");
        }

       n = wolfSSL_read(ssl, recvLine, sizeof(recvLine)-1);
       
       if (n < 0) {
            int readErr = wolfSSL_get_error(ssl, 0);
	        if(readErr != SSL_ERROR_WANT_READ) {
		        printf("CyaSSL_read failed");
            }
       }

        recvLine[n] = '\0';  
        fputs(recvLine, stdout);
    }
}
