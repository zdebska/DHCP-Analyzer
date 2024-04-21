CC = gcc
CFLAGS = -Wall -Werror
LDFLAGS = -lpcap -lm -lncurses

SRCS = dhcp-stats.c
OBJS = $(SRCS:.c=.o)

.PHONY: all clean

all: dhcp-stats

dhcp-stats: dhcp-stats.c 
	$(CC) $(CFLAGS) -o dhcp-stats dhcp-stats.c $(LDFLAGS)

clean:
	rm -f $(OBJS) $(TARGET)