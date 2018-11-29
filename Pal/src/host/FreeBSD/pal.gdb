echo Graphene GDB Script loaded\n

set env IN_GDB = 1

handle SIGCONT pass noprint nostop

#set disable-randomization off
set detach-on-fork off
set schedule-multiple on
set follow-exec-mode same
set follow-fork-mode child
