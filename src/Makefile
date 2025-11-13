# Copyright (c) Mohammad Abbasi <mohammad.v184@gmail.com>

CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2
LDFLAGS ?= -lubus -lubox -lcurl


# Source and output
SRC := $(wildcard *.c)
DEPS := $(wildcard *.h)
OBJ := $(SRC:.c=.o)



# Default target
all: arvancloud-cloudlogs

# Compile source files into object files
%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

# Link the final executable
arvancloud-cloudlogs: $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

# Clean build artifacts
clean:
	rm -f arvancloud-cloudlogs $(OBJ) *.o

.PHONY: all clean install


