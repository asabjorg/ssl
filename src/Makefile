CC = gcc
CFLAGS = -std=gnu11 -O2 -g -Wall -Wno-unused-variable -Wno-unused-parameter -Wextra -Wformat=2 $(shell pkg-config glib-2.0 openssl --cflags)

all: chatd chat 

chat: chat.o chat_helpers.o
	$(CC) $(CFLAGS) -o $@ $^ -lreadline $(shell pkg-config glib-2.0 openssl --libs)

#chatd: chatdOLD.o chat_helpers.o
#chatd: test.o chat_helpers.o
chatd: chatd.o chat_helpers.o
	$(CC) $(CFLAGS) -o $@ $^ $(shell pkg-config glib-2.0 openssl --libs)

clean:
	rm -f *.o *~

distclean: clean
	rm -f chatd chat
