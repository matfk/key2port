CC := gcc
CFLAGS := -std=c11 -Wall -Wextra -fvisibility=hidden -D_DEFAULT_SOURCE
DEBUG ?= 1

ifeq ($(DEBUG),1)
CFLAGS += -g -O0
else
CFLAGS += -O2 -DNDEBUG
endif

EXTRA_INC ?=
EXTRA_LIBS ?= -lsodium -lpcap

SRC_DIR := src
CORE_DIR := $(SRC_DIR)/core
SPA_DIR := $(SRC_DIR)/libspa
CLIENT_DIR := $(SRC_DIR)/client
SERVER_DIR := $(SRC_DIR)/server

OBJDIR := build
COREOBJ := $(OBJDIR)/core
SPAOBJ := $(OBJDIR)/spa
CLIOBJ := $(OBJDIR)/client
SRVOBJ := $(OBJDIR)/server

INCLUDES := -I$(SRC_DIR)

# sources
CORE_SRCS := $(wildcard $(CORE_DIR)/*.c)
SPA_SRCS  := $(wildcard $(SPA_DIR)/*.c)
CLIENT_SRCS := $(wildcard $(CLIENT_DIR)/*.c)
SERVER_SRCS := $(wildcard $(SERVER_DIR)/*.c)

CORE_OBJS := $(patsubst $(CORE_DIR)/%.c,$(COREOBJ)/%.o,$(CORE_SRCS))
SPA_OBJS  := $(patsubst $(SPA_DIR)/%.c,$(SPAOBJ)/%.o,$(SPA_SRCS))
CLIENT_OBJS := $(patsubst $(CLIENT_DIR)/%.c,$(CLIOBJ)/%.o,$(CLIENT_SRCS))
SERVER_OBJS := $(patsubst $(SERVER_DIR)/%.c,$(SRVOBJ)/%.o,$(SERVER_SRCS))

CORE_LIB := $(OBJDIR)/libcore.a
SPA_LIB  := $(OBJDIR)/libspa.a

CLIENT_BIN := client
SERVER_BIN := server

.PHONY: all clean core spa client server

all: $(SERVER_BIN) $(CLIENT_BIN)

# core objects
$(COREOBJ)/%.o: $(CORE_DIR)/%.c | $(COREOBJ)
	@echo "CC $<"
	$(CC) $(CFLAGS) $(EXTRA_INC) $(INCLUDES) -c $< -o $@

# spa objects
$(SPAOBJ)/%.o: $(SPA_DIR)/%.c | $(SPAOBJ)
	@echo "CC $<"
	$(CC) $(CFLAGS) $(EXTRA_INC) $(INCLUDES) -c $< -o $@

# client objects
$(CLIOBJ)/%.o: $(CLIENT_DIR)/%.c | $(CLIOBJ)
	@echo "CC $<"
	$(CC) $(CFLAGS) $(EXTRA_INC) $(INCLUDES) -c $< -o $@

# server objects
$(SRVOBJ)/%.o: $(SERVER_DIR)/%.c | $(SRVOBJ)
	@echo "CC $<"
	$(CC) $(CFLAGS) $(EXTRA_INC) $(INCLUDES) -c $< -o $@

$(CORE_LIB): $(CORE_OBJS) | $(OBJDIR)
	@echo "AR $@"
	ar rcs $@ $(CORE_OBJS)

$(SPA_LIB): $(SPA_OBJS) $(CORE_LIB) | $(OBJDIR)
	@echo "AR $@"
	ar rcs $@ $(SPA_OBJS)

$(CLIENT_BIN): $(CLIENT_OBJS) $(SPA_LIB) $(CORE_LIB)
	@echo "LINK $@"
	$(CC) $(CFLAGS) $(CLIENT_OBJS) $(SPA_LIB) $(CORE_LIB) -o $@ $(EXTRA_LIBS)

$(SERVER_BIN): $(SERVER_OBJS) $(SPA_LIB) $(CORE_LIB)
	@echo "LINK $@"
	$(CC) $(CFLAGS) $(SERVER_OBJS) $(SPA_LIB) $(CORE_LIB) -o $@ $(EXTRA_LIBS)

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(COREOBJ):
	mkdir -p $(COREOBJ)

$(SPAOBJ):
	mkdir -p $(SPAOBJ)

$(CLIOBJ):
	mkdir -p $(CLIOBJ)

$(SRVOBJ):
	mkdir -p $(SRVOBJ)

clean:
	rm -rf $(OBJDIR) $(CLIENT_BIN) $(SERVER_BIN)
