LDLIBS=-lpcap

TARGET=arp-spoof

all: $(TARGET)

main.o: main.cpp ethhdr.h arphdr.h ip.h mac.h
	$(CXX) $(CXXFLAGS) -c -o $@ main.cpp

ip.o: ip.cpp ip.h
	$(CXX) $(CXXFLAGS) -c -o $@ ip.cpp

mac.o: mac.cpp mac.h
	$(CXX) $(CXXFLAGS) -c -o $@ mac.cpp

$(TARGET): main.o ip.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f $(TARGET) *.o
