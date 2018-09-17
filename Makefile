all:
	gcc -g ack.c utils.c clientsw.c message.c cliente.c -o cliente -lcrypto -lrt
	gcc -g utils.c clientlist.c serversw.c message.c servidor.c -o servidor -lpthread -lcrypto -lrt
