/* wolfSSL Sock Addr */
#include <wolfssl/ssl.h>

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

/* Socket base*/
typedef struct {
    uint8_t             domain;
    uint8_t             type;
    uint8_t             protocol;
#ifdef MODULE_TCP
    tcp_cb_t            tcp_control;
#endif
    sockaddr6_t         local_address;
    sockaddr6_t         foreign_address;
} socket_t;

typedef struct {
    uint8_t             socket_id;
    uint8_t             recv_pid;
    uint8_t             send_pid;
    socket_t            socket_values;
#ifdef MODULE_TCP
    uint8_t             tcp_input_buffer_end;
    mutex_t             tcp_buffer_mutex;
    uint8_t             tcp_input_buffer[TRANSPORT_LAYER_SOCKET_MAX_TCP_BUFFER];
#endif
} socket_internal_t;