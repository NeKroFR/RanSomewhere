CC = x86_64-w64-mingw32-gcc
CFLAGS = -Wall -g
LDFLAGS = -lws2_32 -lbcrypt
SRC = $(wildcard client/*.c)
OBJ = $(SRC:client/%.c=%.o)
EXEC = RanSomewhere.exe

all: $(EXEC)
	rm -f $(OBJ)

$(EXEC): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: client/%.c
	$(CC) -c $< $(CFLAGS)

clean:
	rm -f $(OBJ) $(EXEC)

.PHONY: clean
