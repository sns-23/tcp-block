CC = gcc
CFLAGS = -g -Wall
LDFLAGS = -lpcap
OBJS = main.o util.o checksum.o

tcp-block: $(OBJS)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS) $(LDFLAGS) 

clean:
	rm -rf tcp-block *.o

.PHONY:
	tcp-block clean