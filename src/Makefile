BINARY=bzsprof
ifdef DEBUG
LIBBLAZESYM=../blazesym/target/debug/libblazesym.a
CFLAGS:= -I../blazesym/target/debug -g
RUST_FLAGS:=
else
LIBBLAZESYM=../blazesym/target/release/libblazesym.a
CFLAGS:= -I../blazesym/target/release -O
RUST_FLAGS:= --release
endif
LDFLAGS:= $(LIBBLAZESYM) -lrt -pthread -ldl

all:: $(BINARY)

$(BINARY): bzsprof.o $(LIBBLAZESYM)
	$(CC) -o $@ $< $(LDFLAGS)

bzsprof.o: bzsprof.c $(LIBBLAZESYM)
	$(CC) -c $< $(CFLAGS)

$(LIBBLAZESYM):
	cd ../blazesym && cargo build $(RUST_FLAGS) --features="cheader"

clean::
	rm -f *.o $(BINARY)
	cd ../blazesym && cargo clean
