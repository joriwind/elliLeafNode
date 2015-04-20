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
 
 
/* Configure program here */
#define CUSTOM_IO
//#define NO_FILESYSTEM
//#define SHELL //NOT supported

#include <stdio.h>
#include <string.h>

#include "posix_io.h"
#ifdef SHELL
   #include "shell.h"
   #include "shell_commands.h"
#endif
#include "periph/cpuid.h" 
#include "board_uart0.h"
#include "random.h"
#include "thread.h"
#include <coap.h>


#ifdef CUSTOM_IO
   #include "inet_pton.h"
   #include "udp.h"
   #include "net_help.h"
   #include "net_if.h"
   //#include "netinet/in.h"
   #include "socket_base/socket.h"
#else
   //#include <sys/types.h>
   #include <sys/socket.h>
   //#include <netinet/in.h>
   #include <netdb.h>
   #include <arpa/inet.h>
   //#include <stdlib.h>
   //#include <unistd.h>
#endif


#include <wolfssl/ssl.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/memory.h>

//#define CUSTOM_RAND_GENERATE  rand_gen

#define MAXLINE   4096
#define SERV_PORT 5683 

//Setting size of thread stack, to max
char t2_stack[KERNEL_CONF_STACKSIZE_MAIN];

/* Functions */
int main(void);
static void _init_tlayer(void);
static uint16_t get_hw_addr(void);

int newCoapClient(void);
void *second_thread(void *arg);
void DatagramClient (WOLFSSL* ssl);
int CbIORecv(WOLFSSL* ssl, char* buf, int sz, void* ctx);
int CbIOSend(WOLFSSL* ssl, char* buf, int sz, void* ctx);
word32 rand_gen2(void);