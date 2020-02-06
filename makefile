HOST_SYSTEM = $(shell uname | cut -f 1 -d_)
SYSTEM ?= $(HOST_SYSTEM)
CXX = g++
CPPFLAGS += `pkg-config --cflags openssl`
CXXFLAGS += -std=c++11
LDFLAGS += -L /usr/local/lib `pkg-config --libs openssl` -g

all: test

%.o : %.cc
	$(CXX) $^ -o $@ -c $(CPPFLAGS)

test: test.o
	$(CXX) $^ -o $@ $(LDFLAGS)



clean:
	rm -f *.o test

