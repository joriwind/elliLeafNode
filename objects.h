/* wolfSSL Sock Addr */
#include <wolfssl/ssl.h>
#include "main.h"

/* wolfSSL Sock Addr */
struct WOLFSSL_SOCKADDR {
    unsigned int sz; /* sockaddr size */
    void*        sa; /* pointer to the sockaddr_in or sockaddr_in6 */
};

typedef struct WOLFSSL_DTLS_CTX {
    WOLFSSL_SOCKADDR peer;
    int fd;
} WOLFSSL_DTLS_CTX;

typedef struct WOLFSSL_FLAGS {
    int             rflags;             /* user read  flags */
    int             wflags;             /* user write flags */

}WOLFSSL_FLAGS;

