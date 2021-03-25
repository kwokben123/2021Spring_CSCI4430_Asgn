all: myids testattack

myids: myids.cpp
	g++ -Wall myids.cpp -o myids -lpcap -std=c++11
testattack: testattack.cpp
	g++ -Wall testattack.cpp -o testattack -std=c++11

clean:
	@rm myids testattack
