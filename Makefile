JATTACH_VERSION=1.5

ifneq ($(findstring Windows,$(OS)),)
  CL=cl.exe
  CFLAGS=/O2 /D_CRT_SECURE_NO_WARNINGS
  JATTACH_EXE=jattach.exe
else 
  UNAME_S:=$(shell uname -s)
  ifneq ($(findstring FreeBSD,$(UNAME_S)),)
    CC=cc
    CFLAGS ?= -O2
    JATTACH_EXE=jattach
  else
    ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
    RPM_ROOT=$(ROOT_DIR)/build/rpm
    SOURCES=$(RPM_ROOT)/SOURCES
    SPEC_FILE=jattach.spec
    CC=gcc
    CFLAGS ?= -O2
    JATTACH_EXE=jattach
  endif
endif

all: build build/$(JATTACH_EXE)

build:
	mkdir -p build

build/jattach: src/jattach_posix.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -DJATTACH_VERSION=\"$(JATTACH_VERSION)\" -o $@ $^

build/jattach.exe: src/jattach_windows.c
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
