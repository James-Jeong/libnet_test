all: test_libH

test_libH: test_libH.o mod_Eth.o mod_IP.o mod_TCP.o mod_UDP.o
	gcc -o test_libH test_libH.o mod_Eth.o mod_IP.o mod_TCP.o mod_UDP.o -lpcap

test_libH.o: test_libH.cpp
	gcc -c -o test_libH.o test_libH.cpp

mod_Eth.o: mod_Eth.cpp
	gcc -c -o mod_Eth.o mod_Eth.cpp

mod_IP.o: mod_IP.cpp
	gcc -c -o mod_IP.o mod_IP.cpp

mod_TCP.o: mod_TCP.cpp
	gcc -c -o mod_TCP.o mod_TCP.cpp

mod_UDP.o: mod_UDP.cpp
	gcc -c -o mod_UDP.o mod_UDP.cpp

clean:
	rm -f *.o
	rm -f test_libH

.PHONY : clean

