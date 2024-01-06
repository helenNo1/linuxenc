enc: enc.cpp
	make clean
	g++ -g enc.cpp -lpthread -lcrypto -ldl  -o enc
encprocess:  foreach.cpp encprocess.cpp
	make clean
	g++ -g encprocess.cpp -lpthread -lcrypto -ldl  -o encprocess
clean: 
	rm -rf enc