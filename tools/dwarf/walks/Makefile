CC := gcc
CSOLAGS := -I/root/1ext/code/libdwarf-0.4.2/src/lib/libdwarf
DWARF_OBJ := /root/1ext/code/libdwarf-0.4.2/src/lib/libdwarf/.libs/libdwarf.a
DWRAF_SO := dwarf_walk.so
ADD_LIBS := -lz

SUBDIRS=samelf

all: dl_test $(SUBDIRS)

$(SUBDIRS): ECHO
	make -C $@

ECHO:
	@echo $(SUBDIRS)

cJSON.o: cJSON.c cJSON.h
	$(CC) -c $< -o $@ -fPIC -g

walks.o: walks.c cJSON.h
	$(CC) -c $< -o $@ -fPIC -g $(CSOLAGS)

$(DWRAF_SO): walks.o cJSON.o
	$(CC) -o $@ walks.o cJSON.o -shared -fPIC $(ADD_LIBS) $(DWARF_OBJ)

dl_test.o: dl_test.c cJSON.h
	$(CC) -c $< -o $@ -g

dl_test: dl_test.o $(DWRAF_SO)
	$(CC) -o $@ dl_test.o -ldl

clean:
	$(foreach N, $(SUBDIRS),make clean -C $(N);)
	rm -f *.o *.so dl_test