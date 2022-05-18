BINARY=bzsprof


all:: $(BINARY)

$(BINARY): bzsprof.o
	$(CC) -o $@ $<

bzsprof.o: bzsprof.c
	$(CC) -c $<
