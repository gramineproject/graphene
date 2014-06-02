.\" $X$ xroff -mgs $file
.\" $tty$ groff -mgs $file | colcrt - | more
.\" $lpr$ groff -mgs $file > ${file}.lpr
.\" Define a page top that looks cool
.de PT
.if \\n%>1 \{\
.	sp -.1i
.	ps 14
.	ft 3
.	nr big 24
.	nr space \\w'XXX'
.	nr titlewid \\w'\\*[title]'
.	nr barwid (\\n[LL]-(\\n[titlewid]+(2*\\n[space])))/2
.	ds ln \\l'\\n[barwid]u'\\h'-\\n[barwid]u'\v'-.25'
.	ds bar \\s(\\n[big]\\*(ln\\*(ln\\*(ln\\*(ln\\*(ln\v'1.25'\\h'\\n[barwid]u'\\s0
.	ce 1
\\*[bar]\h'\\n[space]u'\v'-.15'\\*[title]\v'.15'\h'\\n[space]u'\\*[bar]
.	ps
.	sp -.70
.	ps 12
\\l'\\n[LL]u'
.	ft
.	ps
.\}
..
.\" Define a page bottom that looks cool
.de BT
.	ps 9
\v'-1'\\l'\\n(LLu'
.	sp -1
.	tl '\(co 1994 \\*[author]'\\*(DY'%'
.	ps
..
.\" Configuration
.VARPS
.nr HM 1.0i
.nr FM 1i
.if t .nr PO .75i
.if t .nr LL 7.0i
.if n .nr PO .25i
.if n .nr LL 7.5i
.nr PS 11
.nr VS \n(PS+2
.ds title Portable Tools for Performance Analysis
.ds author Larry McVoy
.TL
lmbench:
.sp .5
\*[title]
.br
\s8Revision $Revision$ of $Date$\s0
.AU
\*[author]
.AI
.ps -2
lm@sgi.com\**
(415) 390-1804
.ps +2
.AB
A description of a set benchmarks for measuring system performance.
The benchmarks include latency measurements of basic system operations
such as memory, processes, networking, and disks, and bandwidth measurements
of memory, disks, and networking.
The benchmarks have been run under a wide variety of Unix systems.
The benchmarks are freely distributed under
the GNU General Public License, with the additional restriction 
that results may be reported only if the benchmarks are unmodified.
.AE
.sp 2
.if t .2C
.FS
This work was mostly done while the author was an employee of Sun Microsystems
Computer Corporation.
.FE
.NH 1
Introduction
.LP
The purpose of this project is to provide the computer community with tools
for performance analysis of basic operations of their computer systems.
The tools are designed
to be both portable and comparable over a wide set of Unix systems.\**
.FS
The tools have been run on 
AIX,
BSDI,
HP-UX,
IRIX,
Linux,
NetBSD,
OSF/1,
Solaris,
and
SunOS by the author.
.FE
The interfaces that the tools use have been carefully chosen to be as portable 
and standard as possible.  It is an explicit intent of the benchmark to measure
standard interfaces.  Users of this benchmark may not report results from
modified versions of the benchmarks.\**
.FS
For example, the context switch benchmark may not use a \f(CWyield()\fP
primitive instead of pipes; the networking benchmarks must use the socket
interfaces, not TLI or some other interface.
.FE
.PP
The purpose of
this document is to describe each of the benchmarks.  
.PP
The benchmarks are loosely divided into latency, bandwidth, and ``other''
categories.
.NH 1
Latency measurements
.LP
The latency measurements included in this suite are process creation times
(including address space extension via mmap()),
basic operating system entry cost, context switching, inter process
communication, file system latency, 
disk latency (you must be the super user to get
disk latency results), and memory latency.
.PP
Process benchmarks are used to measure the basic process primitives,
such as creating a new process, running a different program, and context 
switching.  Process creation benchmarks are of particular interest
to distributed systems since many remote operations include the creation
of a remote process to shepherd the remote operation to completion.
Context switching is important for the same reasons.
.PP
Inter process communication latency is important because many operations
are control messages that tell another process (frequently on another
system) to do something.  The latency of telling the remote process to
do something is pure overhead and is frequently in the critical path
of important functions, such as distributed databases.\**
.FS
The performance of the TCP latency benchmark has proven to be a good
estimate of the performance of the Oracle database lock manager.
.FE
.PP
The inter process communication latency benchmarks are roughly the same
idea: pass a small message (a byte or so) back and forth between two
processes.  The reported results are always the microseconds it takes
to do one round trip.  If you are interested in a one way timing, then
about half the round trip is right (however, the CPU cycles tend to be
somewhat asymmetric for a one trip).  
.NH 2
Process forks/exits
.LP
Create a child process which does nothing but 
terminate.  Results are reported in creations per second.  
The benchmark is measuring how fast the OS can create a new address
space and process context.
The child process is spawned via the \f(CBfork\fP() interface,
not the \f(CBvfork\fP() interface. 
.NH 2
Simple process creates I
.LP
Create a child process which then runs a new program that does nothing
but print ``hello world'' and exit.  The difference between this 
benchmark and the previous is the running of a new program.  The
time difference between this and the previous benchmark is the cost
of starting a new (simple) program.  That cost is especially noticeable
on (some) systems that have shared libraries.  Shared libraries can
introduce a substantial (10s of milliseconds) start up cost.  This 
benchmark is intended to quantify the time/space tradeoff of shared
libraries.
.NH 2
Simple process creates II
.LP
Create a child process which runs the same new program except that the
program is started by the system shell.  This is a clone of the C
library \f(CBsystem\fP() interface.  The intent is to educate users
about the cost of this interface.  I have long felt that using the
Bourne shell, especially a dynamically linked Bourne shell, to start up
processes is over kill; perhaps these numbers will convince others of the
same thing.  A better choice would be Plan 9's \f(CBrc\fP shell (which
is, by the way, free software).
.NH 2
Memory mapping 
.LP
Memory mapping is the process of making a file part of a process' address
space, allowing direct access to the file's pages.  It is an alternative
to the traditional read and write interfaces.  Memory mapping is extensively
used for linking in shared libraries at run time.  This benchmark measures
the speed at which mappings can be created as well as removed.  Results
are reported in mappings per second, and the results can be graphed as the
test is run over a series of different sizes.
.NH 2
Context switches
.LP
Measures process context switch time.\**  A context switch is defined as 
the time it takes to save the state of one process and restore the state
of another process.
Typical context switch benchmarks measure just the minimal context switch
time, i.e., the time to switch between two processes that are doing nothing
but context switching.  That approach is misleading because systems may
have multiple active processes and the processes typically have more state
(hot cache lines) than just the code required to force another context
switch.  This benchmark takes that into consideration and varies both
the number and the size of the processes.
.FS
A previous version of this benchmark included several system calls
in addition to the context switch, resulting in grossly over inflated
context switch times.
.FE
.PP
The benchmark is a ring of two to twenty processes that are connected
with Unix pipes.  A token is passed from process to process, forcing
context switches.  The benchmark measures the time it takes to pass
the token two thousand times from process to process.  Each hand off
of the token has two costs: (a) the context switch, and (b) the cost 
of passing the token.  In order to get just the context switching time,
the benchmark first measures the cost of passing the token through a 
ring of pipes in a single process.  This time is defined as the cost 
of passing the token and is not included in the reported context switch
time.
.PP
When the processes are larger than the default baseline of ``zero''
(where zero means just big enough to do the benchmark), the cost
of the context switch includes the cost of restoring user level
state (cache lines).  This is accomplished by having the process
allocate an array of data and sum it as a series of integers
after receiving the token but before passing the token to the
next process.  Note that the overhead mentioned above includes 
the cost of accessing the data but because it is measured in 
just one address space, the cost is typically the cost with hot
caches.  So the context switch time does not include anything
other than the context switch provided that all the processes
fit in the cache.  If there are cache misses (as is common), the
cost of the context switch includes the cost of those cache misses.
.PP
Results for an HP system running at 100 mhz are shown below.  
This is a particularly nice system for this benchmark because the
results are quite close to what is expected from a machine with a
256KB cache.  As the size and number of processes are both increased,
processes start falling out of the cache, resulting in higher context
switch times.
.LP
.so ctx.pic
.NH 2
Null system calls
.LP
Measures the cost of entering and exiting (without pausing) the
operating system.  This is accomplished by repeatedly writing one byte
to \f(CB/dev/null\fP, a pseudo device driver that does nothing but
discard the data.  Results are reported as system calls per second.
.PP
It is important to note that the system call chosen actually does the
work on all systems, to the best of my knowledge.  There are some
systems that optimized trivial system calls, such as \f(CBgetpid\fP(),
to return the answer without a true entry into the OS proper.  Writing
to \f(CB/dev/null\fP has not been optimized.
.NH 2
Pipe latency
.LP
This benchmark measures the OS; there is almost no code executed at
user level.  The benchmark measures the round trip time of a small message
being passed back and forth between two processes through a pair of
Unix pipes.
.NH 2
TCP/IP latency
.LP
This benchmark measures the OS
networking code and the driver code; there is almost no code executed at
user level.  The benchmark measures the round trip time of a small message
being passed back and forth between two processes through an AF_INET
socket.  Note that both remote and local results may be reported.
.NH 2
UDP/IP latency
.LP
This benchmark measures the OS
networking code and the driver code; there is almost no code executed at
user level.  The benchmark measures the round trip time of a small message
being passed back and forth between two processes through an AF_INET socket.
Note that both remote
and local results may be reported.
.LP
It is interesting to note that the TCP performance is sometimes
greater than the UDP performance.  
This is contrary to expectations since
the TCP protocol is a reliable, connection oriented protocol, and as such
is expected to carry more overhead.
Why this is so is an exercise left to the
reader.
.NH 2
RPC latency (TCP and UDP)
.LP
Actually two latency benchmarks: Sun RPC over TCP/IP and over UDP/IP.
This benchmark consists of the user level RPC code layered over the TCP
or UDP sockets.  The benchmark measures the round trip time of a small
message being passed back and forth between two processes.  Note that
both remote and local results may be reported.
.LP
Using the TCP or the UDP benchmarks as a baseline, it 
is possible to see how much the RPC code is costing.  
.NH 2
TCP/IP connect latency
.LP
This benchmarks measures the time it takes to get a TCP/IP socket and
connect it to a remote server.
.NH 2
File system latency
.LP
A benchmark that measures how fast the file system can do basic, common 
operations, such as creates and deletes of small files.  
.NH 2
Page fault latency
.LP
A benchmark that measures how fast the file system can pagefault in a
page that is not in memory.
.NH 2
Disk latency
.LP
A benchmark that is designed to measure the overhead of a disk
operation.  Results are reported as operations per second.
.PP
The benchmark is designed with SCSI disks in mind.  It actually simulates
a large number of disks in the following way.  The benchmark reads 512 byte
chunks sequentially from the raw disk device (raw disks are unbuffered
and are not read ahead by Unix).  The benchmark ``knows'' that most
disks have read ahead buffers that read ahead the next 32-128 kilobytes.
Furthermore, the benchmark ``knows'' that the disks rotate and read ahead
faster than the processor can request the chunks of data.\**
.FS
This may not always be true - a processor could be fast enough to make the
requests faster than the rotating disk.  If we take 3MB/sec to be disk
speed, a fair speed, and divide that by 512, that is 6144 IOs/second, or
163 microseconds per IO.  I don't know of any processor/OS/io controller
combinations that can do an
IO in 163 microseconds.
.FE
So the benchmark is basically reading small chunks of data from the
disks track buffer.  Another way to look at this is that the benchmark 
is doing memory to memory transfers across a SCSI channel.
.PP
No matter how you look at it, the resulting number represents a 
\fBlower\fP bound on the overhead of a disk I/O.  In point of fact,
the real numbers will be higher on SCSI systems.  Most SCSI controllers
will not disconnect if the request can be satisfied immediately; that is
the case here.  In practice, the overhead numbers will be higher because
the processor will send the request, disconnect, get interrupted,
reconnect, and transfer.
.PP
It is possible to generate loads of upwards of 500 IOPs on a single
SCSI disk using this technique.  It is useful to do that to figure out
how many drives could be supported on a system before there are no
more processor cycles to handle the load.  Using this trick, you 
do not have to hook up 30 drives, you simulate them.
.NH 2
Memory read latency
.LP
This is perhaps the most interesting benchmark in the suite.  The
entire memory hierarchy is measured, including onboard cache latency
and size, external cache latency and size, main memory latency, and TLB
miss latency.  
.PP
The benchmark varies two parameters, array size and array stride.  
For each size, a list of pointers is created for all of the different 
strides.  Then the list is walked like so
.DS
.ft CB
mov  r0,(r0)  # C code: p = *p;
.DE
The time to do about fifty thousand loads (the list wraps) is measured and
reported.  The time reported is pure latency time and may be zero even though
the load instruction does not execute in zero time.  Zero is defined as one
clock cycle; in other words, the time reported is \fBonly\fP memory latency
time, as it does not include the instruction execution time.  It is assumed
that all processors can do a load instruction (not counting stalls) in one
processor cycle.  In other words, if the processor cache load time
is 60 nanoseconds on a 20 nanosecond processor, the load latency reported
would be 40 nanoseconds, the missing 20 seconds is for the load instruction
itself.  Processors that can manage to get the load address out to the 
address pins before the end of the load cycle get some free time in this
benchmark (I don't think any processors can do that).
.PP
Note that this benchmark has been validated by logic analyzer measurements
on an SGI indy. The
clever reader might realize that last few nanoseconds of inaccuracy could be
rounded off by realizing that the latency is always going to be a multiple
of the processor clock rate.
.PP
The raw data is a series of data sets.  Each data set is a stride size,
with array size varied from about one kilobyte up to eight megabytes.
When these data sets are all plotted together (using a log base 2 scale
for the size variable), the data will be seen to contain a series of 
horizontal plateaus.  The first is the onboard data cache latency (if there
is an onboard cache).  The point where the lines start to go up marks the
size of the cache.  The second is the external cache, the third is the
main memory, and the last is main memory plus TLB miss cost.  In addition
to this information, the cache line size can be derived by noticing which
strides are faster than main memory times.  The first stride that is
main memory speed is likely to be the cache line size.  The reason is
that the strides that are faster than memory indicate that the benchmark is
getting more than one hit per cache line.  Note that prefetching may confuse
you.
.PP
The graph below shows a particularly nicely made machine, a DEC alpha.
This machine is nice because (a) it shows the latencies and sizes of
the on chip level 1 and motherboard level 2 caches, and (b) because it
has the best all around numbers, especially considering it can support a
4MB level 2 cache.  Nice work, DEC.
.so mem.pic
.NH 1
Bandwidth measurements
.LP
One of my former managers\** once noted that ``Unix is Swahili for bcopy().''
I believe that he was indicating his belief that the operating system spent
most of its time moving data from one place to another, via various means.
I tend to agree and have measured the various ways that data can be moved.
The ways that are measured are: through pipes, TCP sockets, library bcopy()
and hand unrolled bcopy(), the read() interface, through the mmap() interface,
and direct memory read and write (no copying).
.FS
Ken Okin
.FE
.NH 2
Pipe bandwidth
.LP
Bandwidth measurement between two local processes communicating through
a Unix pipe.  Results are in megabytes per second.
.NH 2
TCP/IP socket bandwidth
.LP
Bandwidth measurement using TCP/IP sockets.  Results are reported in megabytes
per second.  
Results are reported for local, ethernet, FDDI, and ATM, where possible.  
Results range from 1-10+ megabytes per second.  Any system delivering 
more than 10 MB/second over TCP is doing very well by 1994 standards.
.PP
Note that for local measurements, the system is actually moving 
twice as much data, since the data is being moved to/from the same host.
.PP
Local bandwidths are (sometimes) useful for determining the overhead of the
protocol stack (as well as other OS tasks, such as context switching).  
Note, however, that some implementations (such as Solaris 2.x) have 
``fast pathed'' loopback IP which skews the results.  The fast path
uses a larger MTU and does not do checksums.
.PP
The sockets are configured to use the largest receive/send buffers that the OS
will allow.  This is done to allow maximum bandwidth.  Sun's 4.x TCP/IP
subsystem (and probably BSD's as well) default to 4KB send/receive buffers,
which is too small.  (It would be better if the OS noted that this was a
high volume / high bandwidth connection and automatically grew the buffers.
Hint, hint.)
.NH 2
bcopy bandwidths
.LP
A simple benchmark that measures how fast data can be copied.  A hand
unrolled version and the C library version are tested.  Results are
reported in megabytes per second.  Note that a typical system is actually
moving about three times as much memory as the reported result.  A copy
is actually a read, a write which causes a cache line read, and a write
back.
.NH 2
Read bandwidth
.LP
Most VM system cache file pages for reuse.  This benchmark measures the
speed at which those pages can be reused.  It is important to notice
that this is not a disk read measurement, it is a memory read measurement.
Results are reported in megabytes per second.
.NH 2
Mmap read bandwidth
.LP
The same measurement as the previous benchmark except that it maps the
file, avoiding the copy from kernel to user buffer.  
Results are reported in megabytes per second.
.NH 2
Memory read bandwidth
.LP
A large array is repeatedly read sequentially.
Results reported in megabytes per second.
.NH 2
Memory write bandwidth
.LP
A large array is repeatedly written sequentially.
Results reported in megabytes per second.
.NH 1
Other measurements
.LP
.NH 2
Processor cycle time
mhz
.LP
Calculates the megahertz and clock speed of the processor.  This is the
standard loop in which a series of interlocked operations are timed,
and then the megahertz is derived from the timing.  The operations 
are purposefully interlocked to overcome any super scalerness of the
system under test.
.PP
There are actually three versions of mhz, a generic one that works on
most systems, and two specific versions for SuperSPARC and rs6000
systems.
.PP
It turns out that the
SuperSPARC processor has two ALU's that are run at twice the clock rate,
allowing two interlocked operations to complete in one processor clock.\**
.FS
Credit and thanks to John Mashey of SGI/MIPS fame, who kindly took the
time to out why the benchmark wasn't working on SuperSPARC
systems.  He explained the SuperSPARC pipeline and the solution to the
problem.
.FE
Fortunately, the ALU's are asymmetric and can not do two shifts in
one processor clock.  Shifts are used on SuperSPARC systems.
.PP
IBM rs6000 systems have a C compiler that does not honor the
``register'' directive in unoptimized code.  The IBM loop looks
like it is doing half as many instructions as the others.  This
is on purpose, each add on the IBM is actually two instructions
(I think it is a load/add/store or something like that).
.NH 1
Acknowledgments
.LP
I would like to acknowledge Sun Microsystems for supporting the development
of this project.  In particular,  my personal thanks to Paul Borrill,
Director of the Architecture and Performance group, for conceiving and
supporting the development of these benchmarks.
.PP
My thanks to John Mashey and Neal Nuckolls of Silicon Graphics for reviews,
comments, and explanations of the more obscure problems.
.PP
My thanks to Satya Nishtala of Sun Microsystems for (a) listening to me
complain about memory latencies over and over, (b) doing something about
it in future SPARC systems, and (c) reviewing the memory latency results
and explained IBM's sub blocking scheme (I still don't really understand
it but he does.  Ask him).
.NH 1
Obtaining the benchmarks
.LP
The benchmarks will be posted to the Usenet comp.benchmarks group.  In addition,
mail sent to \f(CBarchives@slovax.engr.sgi.com\fP with a request for 
\f(CBlmbench.shar\fP
sources will get the latest and greatest.
