CC := gcc
CFLAGS := -std=c11 -Wall -Wextra
DEBUG := 1

ifeq ($(DEBUG),1)
CFLAGS += -g -O0
else
CFLAGS += -O2
endif

EXTRA_INC ?=
EXTRA_LIBS ?= -lpcap

SRC_DIR := src
OBJDIR := build
TARGET := occultus

SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst $(SRC_DIR)/%.c,$(OBJDIR)/%.o,$(SRCS))

.PHONY: all clean debug release

all: $(TARGET)

debug:
	$(MAKE) DEBUG=1

release:
	$(MAKE) DEBUG=0

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(EXTRA_INC) -o $@ $^ $(EXTRA_LIBS)

$(OBJDIR)/%.o: $(SRC_DIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) $(EXTRA_INC) -c $< -o $@

$(OBJDIR):
	mkdir -p $(OBJDIR)

clean:
	rm -rf $(OBJDIR) $(TARGET)
