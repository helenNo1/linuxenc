all: enc.cpp
	make clean
	g++ -g enc.cpp -lpthread -lcrypto -ldl  -o enc
clean: 
	rm -rf enc