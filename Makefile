all:
	gcc utils.c slidingwindow.c message.c cliente.c -o cliente -lcrypto -lrt
	gcc utils.c slidingwindow.c message.c servidor.c -o servidor -lpthread -lcrypto -lrt
