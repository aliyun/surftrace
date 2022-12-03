CC := gcc
CFLAG := -g -fpic
LDFLAG := -g -fpic -shared
OBJS := base.o
SO := libbase.so

all: $(SO)

%.o: %.c
	$(CC) -c $< -o $@ $(CFLAG)

$(SO): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAG)

clean:
	rm -f $(SO) $(OBJS)