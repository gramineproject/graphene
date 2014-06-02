handle SIGCONT pass noprint nostop
handle SIGKILL pass print stop

set disable-randomization off
set detach-on-fork off
set schedule-multiple on
set follow-exec-mode same
set follow-fork-mode child

define hook-continue
  inferior 1
end

if $_thread == 0
  tbreak pal_main
  run
end
