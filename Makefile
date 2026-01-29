# mss - macOS Socket Statistics
# Copyright (c) 2026 Murat Kaan Tekeli

CC     = cc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lproc
PREFIX  = /usr/local
BINDIR  = $(PREFIX)/bin

mss: main.c
	$(CC) $(CFLAGS) -o $@ main.c $(LDFLAGS)

all: mss

install: mss
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 mss $(DESTDIR)$(BINDIR)/mss

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/mss

clean:
	rm -f mss

.PHONY: install uninstall clean
