#
# Makefile
# archie, 2018-08-27 23:58
#

all:
	gcc cliente.c -o cliente -lcrypto -lrt
	gcc servidor.c -o servidor -lpthread -lcrypto -lrt
