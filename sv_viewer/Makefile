# Makefile for IEC 61850 Sampled Values Viewer
# Uses libiec61850-1.6.1 and GTK+3

CC = gcc
CFLAGS = -Wall -Wextra -g -O2 `pkg-config --cflags gtk+-3.0`
LDFLAGS = `pkg-config --libs gtk+-3.0` -lpthread

# libiec61850 paths
LIBIEC61850_DIR = ../libiec61850-1.6
LIBIEC61850_INC = $(LIBIEC61850_DIR)/src/common/inc
LIBIEC61850_LIB = $(LIBIEC61850_DIR)/build

# Source files
TARGET = sv_viewer
SRCS = sv_viewer.c

# Include paths
INCLUDES = -I$(LIBIEC61850_INC) \
           -I$(LIBIEC61850_DIR)/src/sampled_values \
           -I$(LIBIEC61850_DIR)/hal/inc \
           -I$(LIBIEC61850_DIR)/src/iec61850/inc \
           -I$(LIBIEC61850_DIR)/src/iec61850/inc_private \
           -I$(LIBIEC61850_DIR)/src/mms/asn1 \
           -I$(LIBIEC61850_DIR)/src/mms/common \
           -I$(LIBIEC61850_DIR)/src/mms/inc \
           -I$(LIBIEC61850_DIR)/src/logging \
           -I$(LIBIEC61850_DIR)/src/r_session \
           -I$(LIBIEC61850_DIR)/config

# Library paths and libraries
LIBS = -L$(LIBIEC61850_LIB) -liec61850 -lm

all: $(TARGET)

$(TARGET): $(SRCS)
	@echo "Building $(TARGET)..."
	$(CC) $(CFLAGS) $(INCLUDES) -o $(TARGET) $(SRCS) $(LDFLAGS) $(LIBS)
	@echo "Build complete: $(TARGET)"

clean:
	rm -f $(TARGET) *.o

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

.PHONY: all clean install
