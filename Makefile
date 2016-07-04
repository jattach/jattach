ifneq ($(findstring Windows,$(OS)),)
  CL=cl.exe
  CFLAGS=/O2 /D_CRT_SECURE_NO_WARNINGS
  JATTACH_EXE=jattach.exe
else
  CC=gcc
  CFLAGS=-O2
  JATTACH_EXE=jattach
endif


all: build build/$(JATTACH_EXE)

build:
	mkdir -p build

build/jattach: src/jattach_linux.c
	$(CC) $(CFLAGS) -o $@ $^

build/jattach.exe: src/jattach_windows.c
	$(CL) $(CFLAGS) /Fobuild/jattach.obj /Fe$@ $^ advapi32.lib

clean:
	rm -rf build
