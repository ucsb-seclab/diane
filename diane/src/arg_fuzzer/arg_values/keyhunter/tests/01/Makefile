
SUBJECT=test01

all: $(SUBJECT).c
	mkdir -p out
	# Use the compiler from Android NDK or gcc for ARM
	arm-linux-gnueabi-gcc $(SUBJECT).c -o out/$(SUBJECT) -Wall
