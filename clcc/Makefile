###########################################
#Makefile for simple programs
###########################################

SUBDIRS=hello event_out hash_map call_stack attach

all:$(SUBDIRS)

$(SUBDIRS):ECHO
	make -C $@

clean:
	$(foreach N, $(SUBDIRS),make clean -C $(N);)

ECHO:
	@echo $(SUBDIRS)