CC := gcc
CFLAG := -g
LDFLAG := -g
OBJS := second.o samelf.o
EXEC := samelf

all: samelf

second.o: second.c second.h
	$(CC) -c $< -o $@ $(CFLAG)

samelf.o: samelf.c second.h
	$(CC) -c $< -o $@ $(CFLAG)

$(EXEC): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAG)

clean:
	rm -f $(EXEC) $(OBJS)