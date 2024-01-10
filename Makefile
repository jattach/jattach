JATTACH_VERSION=2.2

ifneq ($(findstring Windows,$(OS)),)
  CL=cl.exe
  CFLAGS=/O2 /D_CRT_SECURE_NO_WARNINGS
  JATTACH_EXE=jattach.exe
  JATTACH_DLL=jattach.dll
else 
  JATTACH_EXE=jattach

  UNAME_S:=$(shell uname -s)
  ifeq ($(UNAME_S),Darwin)
    CFLAGS ?= -O3 -arch x86_64 -arch arm64 -mmacos-version-min=10.12
    JATTACH_DLL=libjattach.dylib
  else
    CFLAGS ?= -O3
    JATTACH_DLL=libjattach.so
  endif

  ifeq ($(UNAME_S),Linux)
    ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
    RPM_ROOT=$(ROOT_DIR)/build/rpm
    SOURCES=$(RPM_ROOT)/SOURCES
    SPEC_FILE=jattach.spec
  endif
endif


.PHONY: all dll clean rpm-dirs rpm

all: build build/$(JATTACH_EXE)

dll: build build/$(JATTACH_DLL)

build:
	mkdir -p build

build/jattach: src/posix/*.c src/posix/*.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -DJATTACH_VERSION=\"$(JATTACH_VERSION)\" -o $@ src/posix/*.c

build/$(JATTACH_DLL): src/posix/*.c src/posix/*.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -fPIC -shared -fvisibility=hidden -o $@ src/posix/*.c

build/jattach.exe: src/windows/jattach.c
	$(CL) $(CFLAGS) /DJATTACH_VERSION=\"$(JATTACH_VERSION)\" /Fobuild/jattach.obj /Fe$@ $^ advapi32.lib /link /SUBSYSTEM:CONSOLE,5.02

clean:
	rm -rf build

$(RPM_ROOT):
	mkdir -p $(RPM_ROOT)

rpm-dirs: $(RPM_ROOT)
	mkdir -p $(RPM_ROOT)/SPECS
	mkdir -p $(SOURCES)/bin
	mkdir -p $(RPM_ROOT)/BUILD
	mkdir -p $(RPM_ROOT)/SRPMS
	mkdir -p $(RPM_ROOT)/RPMS
	mkdir -p $(RPM_ROOT)/tmp

rpm: rpm-dirs build build/$(JATTACH_EXE)
	cp $(SPEC_FILE) $(RPM_ROOT)/
	cp build/jattach $(SOURCES)/bin/
	rpmbuild -bb \
                --define '_topdir $(RPM_ROOT)' \
                --define '_tmppath $(RPM_ROOT)/tmp' \
                --clean \
                --rmsource \
                --rmspec \
                --buildroot $(RPM_ROOT)/tmp/build-root \
                $(RPM_ROOT)/jattach.spec
