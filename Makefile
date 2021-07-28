CFLAGS += -Wall

ethpkt: main.o
	$(CC) $(LDFLAGS) $< -o $@
