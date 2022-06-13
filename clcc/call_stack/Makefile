###########################################
#Makefile for simple programs
###########################################
INC= -I../include
LIB= -lpthread -ldl

LCC=clcc
CC=gcc
CC_FLAG=-Wall -g

PRG=call_stack
OBJ=call_stack.o
BPF_FILE=call_stack.bpf.c
BFP_SO=call_stack.so

$(PRG): $(BFP_SO) $(OBJ)
	$(CC) $(LIB) -o $@ $(OBJ)

$(BFP_SO): $(BPF_FILE)
	$(LCC) -f $(BPF_FILE)

%.o: %.c
	$(CC) $(CC_FLAG) $(INC) -c $< -o $@

.PRONY:clean
clean:
	@echo "Removing linked and compiled files......"
	rm -f $(OBJ) $(PRG) $(BFP_SO)