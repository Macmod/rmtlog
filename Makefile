all:
	gcc -g -D_REENTRANT -DDEBUG=false ack.c utils.c clientsw.c message.c cliente.c -o cliente -lcrypto -lrt
	gcc -g -D_REENTRANT -DDEBUG=false utils.c clientlist.c serversw.c message.c servidor.c -o servidor -lpthread -lcrypto -lrt

debug:
	gcc -g -D_REENTRANT -DDEBUG=true ack.c utils.c clientsw.c message.c cliente.c -o cliente -lcrypto -lrt
	gcc -g -D_REENTRANT -DDEBUG=true utils.c clientlist.c serversw.c message.c servidor.c -o servidor -lpthread -lcrypto -lrt

clean:
	rm {cliente,servidor}
