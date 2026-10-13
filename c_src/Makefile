# c_src/Makefile — build libvaulting_core shared library
#
# Usage:
#   make          — build the shared library (auto-detected OS)
#   make test     — compile and run the standalone C unit test
#   make clean    — remove build artefacts
#
# The library is output to ../vaulting/libvaulting_core.{so,dylib}
# so that the Python native.py loader can find it via __file__.

CC      ?= cc
CFLAGS  := -O2 -march=native -Wall -Wextra -std=c11 -fPIC
LDFLAGS :=

OUTDIR  := ../vaulting
SRC     := vaulting_core.c          # unified include of all .c files
HEADERS := scanner.h secure_mem.h shamir.h

# Detect platform
UNAME := $(shell uname -s)
ifeq ($(UNAME),Darwin)
  SOEXT   := dylib
  SOFLAGS := -dynamiclib -framework Security
else
  SOEXT   := so
  SOFLAGS := -shared
  LDFLAGS += -lpthread
endif

LIB := $(OUTDIR)/libvaulting_core.$(SOEXT)

.PHONY: all test clean

all: $(LIB)

$(LIB): $(SRC) $(HEADERS)
	$(CC) $(CFLAGS) $(SOFLAGS) -o $@ $(SRC) $(LDFLAGS)
	@echo "Built: $@"

# ── standalone C test ────────────────────────────────────────────────────────
TEST_SRC := test_c.c
TEST_BIN := _test_c

test: $(TEST_BIN)
	./$(TEST_BIN)

$(TEST_BIN): $(TEST_SRC) $(SRC) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(TEST_SRC) $(SRC) $(LDFLAGS) \
	    $(if $(filter Darwin,$(UNAME)),-framework Security,)
	@echo "Built test binary: $@"

clean:
	rm -f $(LIB) $(TEST_BIN)
