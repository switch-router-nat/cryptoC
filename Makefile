CC = gcc
CFLAGS = -Wall -g -c
TARGET = libcryptoc.so

ROOT_DIR=$(shell pwd)
SRC_DIR =$(ROOT_DIR)/src
SYSLIB_DIR  = /usr/lib
SYSINC_DIR  = /usr/include
DIRS    =$(shell find $(SRC_DIR) -maxdepth 3 -type d)
FILES   =$(foreach dir,$(DIRS),$(wildcard $(dir)/*.c))
OBJS    =$(patsubst %.c,%.o,$(FILES)) 


all:$(TARGET)

$(TARGET):$(OBJS)
	$(CC) -fPIC -shared -o $(TARGET) $(FILES)
%.o: %.c
	$(CC) $(CFLAGS) $< -o $@
.PHONY: install uninstall clean
install:
	install -d $(SYSLIB_DIR)
	install -m 0755 $(TARGET) $(SYSLIB_DIR)
	cp $(ROOT_DIR)/src/cryptoc.h $(SYSINC_DIR)
	ldconfig
uninstall:
	rm $(SYSLIB_DIR)/$(TARGET)
	rm $(SYSINC_DIR)/cryptoc.h
clean:
	rm -rf $(OBJS) 
	rm -rf $(TARGET)
	rm -rf $(SYSLIB_DIR)/$(TARGET)
