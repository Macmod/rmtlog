all:
	gcc -g utils.c slidingwindow.c message.c cliente.c -o cliente -lcrypto -lrt
	gcc -g utils.c slidingwindow.c message.c servidor.c -o servidor -lpthread -lcrypto -lrt
