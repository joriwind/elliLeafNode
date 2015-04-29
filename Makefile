# name of your application
APPLICATION = elliLeafNode

# If no BOARD is found in the environment, use this default:
BOARD ?= native

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../RIOT/

# Uncomment these lines if you want to use platform support from external
# repositories:
#RIOTCPU ?= $(CURDIR)/../../RIOT/thirdparty_cpu
#RIOTBOARD ?= $(CURDIR)/../../RIOT/thirdparty_boards

# Uncomment this to enable scheduler statistics for ps:
#CFLAGS += -DSCHEDSTATISTICS

# If you want to use native with valgrind, you should recompile native
# with the target all-valgrind instead of all:
# make -B clean all-valgrind

# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
CFLAGS += -DDEVELHELP -DSCHEDSTATISTICS

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

# The global ip adress to set on startup
CFLAGS += -DHOST_IP=\"::1\"

# This will be filled into the neighbour cache on startup
CFLAGS += -DREMOTE_IP=\"::1\" -DREMOTE_MAC=\"3e:94:6e:ea:d3:7b\"

# Modules to include:

USEMODULE += uart0
USEMODULE += config

USEMODULE += ng_nativenet
USEMODULE += ng_nomac
#USEMODULE += ng_netdev_eth

USEMODULE += ng_udp
USEMODULE += ng_ipv6
USEMODULE += ng_netdev_eth
USEMODULE += ng_netif
#USEMODULE += net_if
USEMODULE += ng_pktdump

USEMODULE += random
USEMODULE += libwolfssl

USEMODULE += shell
USEMODULE += shell_commands
USEMODULE += ps

USEPKG=microcoap

include $(RIOTBASE)/Makefile.include
