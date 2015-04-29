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
   #include "net/ng_ipv6/addr.h"
   #include "net/ng_udp.h"
   
   #include "udp_handler.h"
   
   #include "net/ng_netif.h"
   //#include "net/ng_socket.h"
   #include "net/ng_netbase.h"
#else
   //#include <sys/types.h>
   //#include <sys/socket.h>
   //#include <netinet/in.h>
   //#include <netdb.h>
   //#include <arpa/inet.h>
   //#include <stdlib.h>
   //#include <unistd.h>
#endif


#include <wolfssl/ssl.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/random.h>

#include "coap_ext.h"

#define eccCert    "./certs/server-ecc.pem"
#define eccKey     "./certs/ecc-key.pem"

//#define CUSTOM_RAND_GENERATE  rand_gen

#define MAXLINE   4096
#define SERV_PORT 5683 

#define SHA_DIGEST_SIZE 20

//Setting size of thread stack, to max
char t2_stack[KERNEL_CONF_STACKSIZE_DEFAULT];

/* Functions */
int main(void);
static void _init_tlayer(void);
static uint16_t get_hw_addr(void);

int newCoapClient(void);
void *second_thread(void *arg);
void DatagramClient (WOLFSSL* ssl);
void loadCertificates(WOLFSSL_CTX* ctx);
int CbIOGenCookie(WOLFSSL* ssl, byte *buf, int sz, void *ctx);
word32 rand_generator(void);