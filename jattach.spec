Name:		jattach
Version:	1.3
Release:	1
Summary:	JVM Dynamic Attach utility

Group:		Development/Tools
License:	ASL 2.0
URL:		https://github.com/apangin/jattach
Vendor:		Andrei Pangin
Packager:	Vadim Tsesko <incubos@yandex.com>

BuildRequires:	gcc
BuildRequires:	make

%description
The utility to send commands to remote JVM via Dynamic Attach mechanism.

All-in-one jmap + jstack + jcmd + jinfo functionality in a single tiny program.
No installed JDK required, works with just JRE.

This is the lightweight native version of HotSpot Attach API:
https://docs.oracle.com/javase/8/docs/jdk/api/attach/spec/

%build
# Do nothing

%install
BIN=%{buildroot}/usr/bin

mkdir -p ${BIN}

install -p -m 555 %{_sourcedir}/bin/jattach ${BIN}

%files
/usr/bin/jattach

%changelog
* Wed Nov 30 2016 Vadim Tsesko <incubos@yandex.com> - 0.1-1
- Initial version
