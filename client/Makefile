# make && make clean
SRC = $(shell find . -name "*.c")

OBJ = $(SRC:.c=.o)

EXEC = RanSomewhere

$(EXEC): $(OBJ)
	gcc -o $@ $^

%.o: %.c
	gcc -c $<

clean:
	rm -f $(OBJ)
# always call clean even without arguments
.PHONY: clean # don't work



