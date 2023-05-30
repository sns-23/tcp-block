CC = gcc
CFLAGS = -g -DLOG_LEVEL=3
LDFLAGS = -lpcap
OBJS = main.o util.o

tcp-block: $(OBJS)
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS) $(LDFLAGS) 

clean:
	rm -rf block *.o

.PHONY:
	tcp-block clean