CFLAGS = -std=gnu99 -Wall -pedantic
LFLAGS = -lpcap
X = ipk-sniffer
$(X): $(X).o
	gcc $(CFLAGS) -o $(X) $(X).o $(LFLAGS)

$(X).o: $(X).c
	gcc $(CFLAGS) -c -o $(X).o $(X).c

clean:
	rm -f $(X) $(X).o