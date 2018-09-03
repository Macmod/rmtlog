#
# Makefile
# archie, 2018-08-27 23:58
#

all:
	gcc utils.c message.c cliente.c -o cliente -lcrypto -lrt
	gcc utils.c message.c servidor.c -o servidor -lpthread -lcrypto -lrt
