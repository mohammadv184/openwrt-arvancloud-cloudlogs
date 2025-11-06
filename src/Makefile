# Copyright (c) Mohammad Abbasi <mohammad.v184@gmail.com> - All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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


