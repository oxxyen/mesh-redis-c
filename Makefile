CC       := gcc
CFLAGS   := -std=c11 -Wall -Wextra -Wpedantic -O2 -g -pthread
LDFLAGS  := -lwebsockets -lhiredis -lsodium -lpthread

SRCDIR   := src
INCDIR   := include
OBJDIR   := build
BINDIR   := bin

SERVER   := $(BINDIR)/server
WEB_SERVER := $(BINDIR)/web_server
CLIENT   := $(BINDIR)/client

SERVER_OBJS := $(OBJDIR)/server.o $(OBJDIR)/crypto.o
WEB_OBJS  := $(OBJDIR)/web_server.o
CLIENT_OBJS := $(OBJDIR)/client.o

.PHONY: all clean

all: $(SERVER) $(WEB_SERVER) $(CLIENT)

$(OBJDIR):
	mkdir -p $@

$(BINDIR):
	mkdir -p $@

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -I$(INCDIR) -c $< -o $@

$(SERVER): $(SERVER_OBJS) | $(BINDIR)
	$(CC) $^ $(LDFLAGS) -o $@

$(WEB_SERVER): $(WEB_OBJS) | $(BINDIR)
	$(CC) $^ $(LDFLAGS) -o $@

$(CLIENT): $(CLIENT_OBJS) | $(BINDIR)
	$(CC) $^ $(LDFLAGS) -o $@

clean:
	rm -rf $(OBJDIR) $(BINDIR)

install-deps:
	sudo pacman -S libwebsockets hiredis libsodium