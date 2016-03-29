all: build/jattach

build/jattach: src/jattach.c
	mkdir -p build
	gcc -O2 -o $@ $^

clean:
	rm -rf build
