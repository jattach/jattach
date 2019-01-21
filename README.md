## jattach

### JVM Dynamic Attach utility

The utility to send commands to remote JVM via Dynamic Attach mechanism.

All-in-one **jmap + jstack + jcmd + jinfo** functionality in a single tiny program.  
No installed JDK required, works with just JRE. Supports Linux containers.

This is the lightweight native version of HotSpot Attach API  
https://docs.oracle.com/javase/8/docs/jdk/api/attach/spec/

[Supported commands](http://hg.openjdk.java.net/jdk8u/jdk8u/hotspot/file/812ed44725b8/src/share/vm/services/attachListener.cpp#l388):
 - **load**            : load agent library
 - **properties**      : print system properties
 - **agentProperties** : print agent properties
 - **datadump**        : show heap and thread summary
 - **threaddump**      : dump all stack traces (like jstack)
 - **dumpheap**        : dump heap (like jmap)
 - **inspectheap**     : heap histogram (like jmap -histo)
 - **setflag**         : modify manageable VM flag
 - **printflag**       : print VM flag
 - **jcmd**            : execute jcmd command

### Examples
#### Load JVMTI agent

    $ jattach <pid> load <.so-path> { true | false } [ options ]

Where `true` means that the path is absolute, `false` -- the path is relative.

`options` are passed to the agent.

#### List available jcmd commands 

    $ jattach <pid> jcmd "help -all"

### Installation
#### FreeBSD

On FreeBSD, you can use the following command to install `jattach` package:

    $ pkg install jattach

#### Alpine Linux

On Alpine Linux, you can use the following command to install `jattach` package from the edge/community repository:

    $ apk add --no-cache jattach --repository http://dl-cdn.alpinelinux.org/alpine/edge/community/

#### Archlinux

[jattach](https://aur.archlinux.org/packages/jattach/) package can be installed from [AUR](https://wiki.archlinux.org/index.php/Arch_User_Repository) using one of [AUR helpers](https://wiki.archlinux.org/index.php/AUR_helpers), e.g., `yay`:

    $ yay -S jattach
