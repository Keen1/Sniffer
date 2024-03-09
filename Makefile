CC = gcc
CFLAGS = -Wall -Wextra -g
LDFLAGS = -lpcap

TARGET = Sniffer
SRC = Sniffer.c
all: $(TARGET)
$(TARGET):$(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET)
	