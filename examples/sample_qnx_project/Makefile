# Sample Makefile lacking compiler hardening
CC = qcc
CFLAGS = -O2 -Wall

all: vulnerable_service.o
	$(CC) $(CFLAGS) -o telemetry_daemon vulnerable_service.c
