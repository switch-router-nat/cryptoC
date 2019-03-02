CC     = gcc
SOURCE = $(wildcard *.c)
OBJS   = $(patsubst %.c, %.o, $(SOURCE))
TARGET = test_ecc
LIBS   = -lcryptoc
CFLAGS = -c -g

$(TARGET):$(OBJS)
	$(CC) $(OBJS)  $(LIBS) -o $(TARGET)
%.o:%.c
	$(CC) $(CFLAGS) $< -o $@
.PHONY: clean
clean:
	rm -rf $(OBJS) $(TARGET)
