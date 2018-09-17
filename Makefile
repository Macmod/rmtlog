all:
	gcc -g -DDEBUG=false ack.c utils.c clientsw.c message.c cliente.c -o cliente -lcrypto -lrt
	gcc -g -DDEBUG=false utils.c clientlist.c serversw.c message.c servidor.c -o servidor -lpthread -lcrypto -lrt

debug:
	gcc -g -DDEBUG=true ack.c utils.c clientsw.c message.c cliente.c -o cliente -lcrypto -lrt
	gcc -g -DDEBUG=true utils.c clientlist.c serversw.c message.c servidor.c -o servidor -lpthread -lcrypto -lrt
