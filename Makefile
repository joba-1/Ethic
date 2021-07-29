CFLAGS += -Wall

ethic: main.o
	$(CC) $(LDFLAGS) $< -o $@
