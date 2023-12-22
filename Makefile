CC     = cc
CFLAGS = -Wall -Werror -pedantic
LIBS   = -lcrypto
TARGET = vigik

.PHONY: default all clean

default: $(TARGET)
all: default

OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c))
HEADERS = $(wildcard *.h)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -Wall $(LIBS) -o $@
	strip $@

clean:
	-rm -f *.o
	-rm -f $(TARGET)
