## jattach

### JVM Dynamic Attach utility

The utility to send commands to remote JVM via Dynamic Attach mechanism.

All-in-one **jmap + jstack + jcmd + jinfo** functionality in a single tiny program.  
No installed JDK required, works with just JRE.

This is the lightweight native version of HotSpot Attach API  
https://docs.oracle.com/javase/8/docs/jdk/api/attach/spec/

Supported commands:
 - **load**            : load agent library
 - **properties**      : print system properties
 - **agentProperties** : print agent properties
 - **datadump**        : heap histogram
 - **threaddump**      : dump all stack traces (like jstack)
 - **dumpheap**        : dump heap (like jmap)
 - **inspectheap**     : heap histogram (like jmap -histo)
 - **setflag**         : modify manageable VM flag
 - **printflag**       : print VM flag
 - **jcmd**            : execute jcmd command
