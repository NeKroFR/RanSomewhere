CC = x86_64-w64-mingw32-gcc
CFLAGS = -Wall -g
LDFLAGS = -lws2_32
SRC = $(wildcard client/*.c)
OBJ = $(SRC:client/%.c=%.o)
EXEC = RanSomewhere.exe

$(EXEC): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)
	rm -f $(OBJ)

%.o: client/%.c
	$(CC) -c $< $(CFLAGS)

clean:
	rm -f $(OBJ) $(EXEC)

.PHONY: clean
