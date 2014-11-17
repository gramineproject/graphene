handle SIGCONT pass noprint nostop
handle SIGKILL pass print stop

set disable-randomization off
set detach-on-fork off
set schedule-multiple on
set follow-exec-mode same
set follow-fork-mode child

catch vfork
commands
	echo [A child process created]\n
	set scheduler-locking on
	continue
end

catch fork
commands
	echo [A child process created]\n
	set scheduler-locking on
	continue
end

catch exec
commands
	echo [Child process begin running]\n
	set scheduler-locking off
	continue
end

define hook-stop
	if $_thread == 0
		echo [Child process exited]\n
		info inferior
	end
end
