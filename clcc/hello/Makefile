###########################################
#Makefile for simple programs
###########################################
INC= -I../include
LIB= -lpthread -ldl

LCC=coolbpf
CC=gcc
CC_FLAG=-Wall -g

PRG=hello
BPF_FILE=$(PRG).bpf.c
BFP_SO=$(PRG).so
OBJ=$(PRG).o

$(PRG): $(BFP_SO) $(OBJ)
	$(CC) $(LIB) -o $@ $(OBJ)

$(BFP_SO): $(BPF_FILE)
	$(LCC) -f $(BPF_FILE)

%.o: %.c
	$(CC) $(CC_FLAG) $(INC) -c $< -o $@ -DSO_NAME=\"$(BFP_SO)\"

.PRONY:clean
clean:
	@echo "Removing linked and compiled files......"
	rm -f $(OBJ) $(PRG) $(BFP_SO)