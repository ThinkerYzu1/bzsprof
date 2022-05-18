BINARY=bzsprof
LIBBLAZESYM=../blazesym/target/release/libblazesym.a
CFLAGS:= -I../blazesym/target/release
LDFLAGS:= $(LIBBLAZESYM) -lrt -pthread -ldl

all:: $(BINARY)

$(BINARY): bzsprof.o $(LIBBLAZESYM)
	$(CC) -o $@ $< $(LDFLAGS)

bzsprof.o: bzsprof.c $(LIBBLAZESYM)
	$(CC) -c $< $(CFLAGS)

$(LIBBLAZESYM):
	cd ../blazesym && cargo build --release --features="cheader"

clean::
	rm -f *.o $(BINARY)
	cd ../blazesym && cargo clean
