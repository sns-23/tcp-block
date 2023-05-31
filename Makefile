CC = gcc
CFLAGS = -g 
LDFLAGS = -lpcap -DUSE_RAWSOCKET
OBJS = main.o util.o checksum.o

tcp-block: $(OBJS)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS) $(LDFLAGS) 

clean:
	rm -rf tcp-block *.o

.PHONY:
	tcp-block clean