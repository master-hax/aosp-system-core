CFLAGS += -Wall -Werror -iquote../include

.PHONY: all clean

all: libmincrypt.a

clean:
	rm -f *.o libmincrypt.a

libmincrypt.a: dsa_sig.o p256.o p256_ec.o p256_ecdsa.o rsa.o sha.o sha256.o
	${AR} rcs $@ $^
