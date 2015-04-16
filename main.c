/*
 * Copyright (C) 2008, 2009, 2010  Kaspar Schleiser <kaspar@schleiser.de>
 * Copyright (C) 2013 INRIA
 * Copyright (C) 2013 Ludwig Ortmann <ludwig.ortmann@fu-berlin.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       Default application that shows a lot of functionality of RIOT
 *
 * @author      Kaspar Schleiser <kaspar@schleiser.de>
 * @author      Oliver Hahm <oliver.hahm@inria.fr>
 * @author      Ludwig Ortmann <ludwig.ortmann@fu-berlin.de>
 *
 * @}
 */

#include <stdio.h>
#include <string.h>

/*
#include "thread.h"
#include "posix_io.h"
#include "shell.h"
#include "shell_commands.h"
#include "board_uart0.h"
#include "malloc.h"*/

#include "net_if.h"
#include "posix_io.h"
#include "shell.h"
#include "shell_commands.h"
#include "board_uart0.h"
#include "udp.h"
#include "sixlowpan.h"
#include "random.h"

#include "thread.h"
#include "socket_base/socket.h"
#include "net_help.h"
#include "inet_pton.h"

#include "./objects.h"

#include <wolfssl/ssl.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/memory.h>

//#define CUSTOM_RAND_GENERATE  rand_gen

#define CUSTOM_IO
//#define NO_FILESYSTEM


#define MAXLINE   4096
#define SERV_PORT 5683 

char t2_stack[KERNEL_CONF_STACKSIZE_MAIN];



int main(void);
int newCoapClient(void);
void *second_thread(void *arg);
void DatagramClient (WOLFSSL* ssl);
int CbIORecv(WOLFSSL* ssl, char* buf, int sz, void* ctx);
int CbIOSend(WOLFSSL* ssl, char* buf, int sz, void* ctx);
word32 rand_gen2(void);

word32 rand_gen2(void){
   return (word32)genrand_uint32();
}

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

void printTest(char *str) {
    printf("%s\n",str);
}
/**
 * Receive function
**/
int CbIORecv(WOLFSSL* ssl, char* buf, int sz, void* ctx){
   int recvd;
   int sd = *(int*)ctx;
   (void)ssl;
   
   socket_internal_t *socket;
   sockaddr6_t sa;
   socket = socket_base_get_socket(sd);
   socket_t *current_socket = &socket->socket_values;
   uint32_t saSz = sizeof(sa);
   sa = current_socket->local_address;
   //memset(&sa, 0, sizeof(sa));
   
   //wolfSSL_dtls_get_peer(ssl, &sa, &sizeof(sa));
   recvd = socket_base_recvfrom(sd, buf, sz, 0, &sa, &saSz); //removed ssl->rflags
   
   if (recvd < 0) {
     printf("Error in CbIORecv: %i\n", recvd);
   }
   else if (recvd == 0) {
     
     printf("Error in CbIORecv: %i Connection closed\n", recvd);
   }

    return recvd;
}

/**
 * Send function
**/
int CbIOSend(WOLFSSL* ssl, char* buf, int sz, void* ctx){
   WOLFSSL_DTLS_CTX* dtlsCtx = (WOLFSSL_DTLS_CTX*)ctx;
   int sd = dtlsCtx->fd;
   int send;
   int len = sz;
   
   /* max payload size = MTU - MAC - AES - IPV6_HDR_LEN - UDP_HDR_LEN
    *              33  = 127 - 25 - 21 - 40 - 8
   */
   if (sz > 32) {
       printf("%i is too large to be sent (max. 33 characters).", sz);
       return 1;
   }
   
   WOLFSSL_FLAGS* flags = (WOLFSSL_FLAGS*)ssl;
   (void) flags;
   /* Print the information on the terminal */
   socket_base_print_internal_socket(socket_base_get_socket(sd));
   if(socket_base_exists_socket(sd)){
      printf("Socket %i exists\n", sd);
   }else{
      printf("Socket %i does not exist\n", sd);
      return -1;
   }
   
   //Retrieve socket and send address
   socket_internal_t *socket;
   sockaddr6_t sa;
   socket = socket_base_get_socket(sd);
   socket_t *current_socket = &socket->socket_values;
   sa = current_socket->local_address;
   uint32_t saSz = sizeof(sa);
   
   //Send data
   send = (int)socket_base_sendto(sd, buf, 32, 0, &sa, saSz); //removed ssl->wflags
   
   if (send < 0) {
        printf("Error in CbIOSend: %i\n", send);
    }
 
    return send;
}


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
    posix_open(uart0_handler_pid, 0);
    net_if_set_src_address_mode(0, NET_IF_TRANS_ADDR_M_SHORT);
    //int id = net_if_get_hardware_address(0);
    //int id_fd = fd_init();
    shell_t shell;
    
    
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
   
   ipv6_register_packet_handler(monitor_pid);
    (void) puts("Welcome to RIOT!");

    shell_init(&shell, shell_commands, UART0_BUFSIZE, shell_readc, shell_putchar);

    shell_run(&shell);
    return 0;
}

int newCoapClient(void){
   int     	sockfd = 0;
   WOLFSSL* 	ssl = 0;
   WOLFSSL_CTX* ctx = 0;
   WOLFSSL_METHOD* method = 0;
   sockaddr6_t servAddr;
   
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
      memset(&servAddr, 0, sizeof(servAddr));
      servAddr.sin6_family = AF_INET;
      servAddr.sin6_port = HTONS(SERV_PORT);
      if (inet_pton(AF_INET6, "::1", &servAddr.sin6_addr) < 1) {
        printf("Error and/or invalid IP address");
        return 1;
      }
      printf("Got new socket object\n");

      wolfSSL_dtls_set_peer(ssl, &servAddr, sizeof(servAddr));

      //if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
      if ( (sockfd = socket_base_socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0) {       
         printf("cannot create a socket.\n"); 
         return 1;
      }

      if (-1 == socket_base_bind(sockfd, &servAddr, sizeof(servAddr))) {
         printf("Error bind failed!\n");
         socket_base_close(sockfd);
         return NULL;
      }
   #else
      
   #endif
      
    
    wolfSSL_set_fd(ssl, sockfd);
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
