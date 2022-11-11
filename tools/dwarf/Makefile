CC := gcc
COLAGS := -I/root/1ext/code/libdwarf-0.4.2/src/lib/libdwarf
DWARF_OBJ := /root/1ext/code/libdwarf-0.4.2/src/lib/libdwarf/.libs/libdwarf.a
ADD_LIBS := -lz

all: dwarf_in

dwarf_in.o: dwarf_in.c
	$(CC) $(COLAGS) -c $< -o $@

dwarf_in: dwarf_in.o $(DWARF_OBJ)
	$(CC) -o $@ $^ $(ADD_LIBS)

clean:
	rm -f *.o