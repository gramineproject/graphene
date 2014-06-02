.\" This document is GNU groff -mgs -t -p -R -s
.\" It will not print with normal troffs, it uses groff features, in particular,
.\" long names for registers & strings.
.\" Deal with it and use groff - it makes things portable.
.\"
.\" $X$ xroff -mgs -t -p -R -s $file
.\" $tty$ groff -mgs -t -p -R -s $file | colcrt - | more
.\" $lpr$ groff -mgs -t -p -R -s $file > ${file}.lpr
.VARPS
.\" Define a page top that looks cool
.\" HELLO CARL!  To turn this off, s/PT/oldPT/
.de draftPT
.\" .tl '\fBDRAFT\fP'Printed \\*(DY'\fBDRAFT\fP'
..
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
.\" HELLO CARL!  To turn this off, s/BT/oldBT/
.de draftBT
.\" .tl '\fBDRAFT\fP'Page %'\fBDRAFT\fP'
..
.de BT
.	ps 9
\v'-1'\\l'\\n(LLu'
.	sp -1
.	tl '\(co 1995 \\*[author]'\\*(DY'%'
.	ps
..
.de SP
.	if t .sp .5
.	if n .sp 1
..
.de BU
.	SP
.	ne 2
\(bu\ 
.	if \\n[.$] \fB\\$1\fP\\$2
..
.nr FIGURE 0
.nr TABLE 0
.nr SMALL .25i
.de TSTART
.	KF
.	if \\n[.$] \s(24\\l'\\n[pg@colw]u'\s0
.	ps -1
.	vs -1
..
.de TEND
.	ps +1
.	vs +1
.	if \\n[.$]=2 \{\
.	sp -.5
\s(24\\l'\\n[pg@colw]u'\s0 \}
.	sp .25
.	nr TABLE \\n[TABLE]+1
.	ce 1
\fBTable \\n[TABLE].\ \ \\$1\fP
.	SP
.	KE
..
.de FEND
.	ps +1
.	vs +1
.	if \\n[.$]=2 \{\
.	sp -.5
\s(24\\l'\\n[pg@colw]u'\s0 \}
.	sp .25
.	nr FIGURE \\n[FIGURE]+1
.	ce 1
\fBFigure \\n[FIGURE].\ \ \\$1\fP
.	SP
.	KE
..
.\" Configuration
.nr PI 3n
.nr HM .95i
.nr FM 1i
.nr PO .95i
.if t .po .95i
.nr LL 6.5i
.if n .nr PO 0i
.if n .nr LL 7.75i
.nr PS 10
.nr VS \n(PS+1
.ds title Portable tools for performance analysis
.ds author Larry McVoy
.ds lmbench \f(CWlmbench\fP
.ds lmdd  \f(CWlmdd\fP
.ds bcopy \f(CWbcopy\fP
.ds connect \f(CWconnect\fP
.ds execlp  \f(CWexeclp\fP
.ds exit \f(CWexit\fP
.ds fork \f(CWfork\fP
.ds gcc \f(CWgcc\fP
.ds getpid \f(CWgetpid\fP
.ds getpid \f(CWgetpid\fP
.ds gettimeofday \f(CWgettimeofday\fP
.ds kill \f(CWkill\fP
.ds memmove \f(CWmemmove\fP
.ds mmap \f(CWmmap\fP
.ds popen  \f(CWpopen\fP
.ds read \f(CWread\fP
.ds stream \f(CWstream\fP
.ds system  \f(CWsystem\fP
.ds uiomove \f(CWuiomove\fP
.ds write \f(CWwrite\fP
.ds yield  \f(CWyield\fP
.\" References stuff
.de RN  \"Reference Name: .RN $1 -- prints the reference prettily
.\"[\s-2\\$1\s+2]\\$2
[\s-1\\$1\s0]\\$2
..
.\" .R1
.\" sort A+DT
.\" database references
.\" label-in-text
.\" label A.nD.y-2
.\" bracket-label \*([. \*(.] ", "
.\" .R2
.TL
\s(14lmbench: Portable tools for performance analysis\s0\**
.AU
\s+2\fR\*[author]\fP\s0
.AI
\fI\s+2Silicon Graphics, Inc.\s0\fP
.AU
\s+2\fRCarl Staelin\fP
.AI
\s+2\fIHewlett-Packard Laboratories\s0\fP
.SP
.AB
\*[lmbench] is a micro-benchmark suite designed to focus
attention on the basic building blocks of many
common system applications, such as databases, simulations, 
software development, and networking.  In almost all
cases, the individual tests are the result of analysis and isolation
of a customer's actual performance problem.  
.\" .SP
These tools can be, and currently are, used to compare different
system implementations from different vendors.
In several cases,
the benchmarks have uncovered previously unknown bugs and design flaws.
The results have shown a strong
correlation between memory system performance and overall performance.
.\" XXX - MP versus uniprocessors?
\*[lmbench] includes an extensible database of
results from systems current as of late 1995.
.AE
.if t .MC 3.05i
.FS
This paper first appeared in the January 1996 Usenix conference proceedings.
The version you are reading has new results as well as some corrections.
.FE
.NH 1
Introduction
.PP
\*[lmbench]
provides a suite of benchmarks that attempt to measure the most commonly
found performance bottlenecks in a wide range of system applications.
These bottlenecks have been identified, isolated, and reproduced in a set
of small micro-benchmarks, which measure 
system latency and bandwidth of data movement among 
the processor and memory, network, file system, and disk.  
The intent is to produce numbers that real
applications can reproduce, rather than the frequently
quoted and somewhat less reproducible marketing performance numbers.
.PP
The benchmarks focus on latency and bandwidth because
performance issues are usually caused by latency
problems, bandwidth problems, or some combination of the two.  Each benchmark
exists because it captures some unique performance problem present in 
one or more important applications.  
For example, the TCP latency benchmark is an accurate predictor of the
Oracle distributed lock manager's performance, the memory latency
benchmark gives a strong indication of Verilog simulation performance,
and the file system latency benchmark models a critical path
in software development.
.PP
\*[lmbench] was developed to identify and evaluate system performance
bottlenecks present in many machines in 1993-1995.  It is entirely
possible that computer architectures will have changed and advanced
enough in the next few years to render parts of this benchmark suite
obsolete or irrelevant.
.PP
\*[lmbench] is already in widespread use at many sites by both end
users and system designers.  In some cases, \*[lmbench] has provided
the data necessary to discover and correct critical performance
problems that might have gone unnoticed.  \*[lmbench] uncovered a
problem in Sun's memory management software
that made all pages map to the same location in the cache, effectively
turning a 512 kilobyte (K) cache into a 4K cache.
.PP
\*[lmbench] measures only a system's ability
to transfer data between processor, cache, memory, network, and disk.
It does not measure other parts of the system, such as the graphics subsystem,
nor is it a MIPS, MFLOPS,
throughput, saturation, stress, graphics, or multiprocessor test suite.  
It is frequently run on multiprocessor (MP) systems to compare their performance
against
uniprocessor systems, but it does not take advantage of any multiprocessor
features.  
.PP
The benchmarks are written using standard, portable 
system interfaces and facilities commonly
used by applications, so 
\*[lmbench]
is portable and comparable over a wide set of Unix systems.
\*[lmbench] has been run on 
AIX,
BSDI,
HP-UX,
IRIX,
Linux,
FreeBSD,
NetBSD,
OSF/1,
Solaris,
and
SunOS.
Part of the suite has been run on Windows/NT as well.
.PP
\*[lmbench]
is freely distributed under
the Free Software Foundation's General Public License
.RN Stallman89 ,
with the additional restriction 
that results may be reported only if the benchmarks are unmodified.
.NH 1
Prior work
.PP
Benchmarking and performance analysis is not a new endeavor.
There are too many other benchmark suites to list all of
them here.  We compare \*[lmbench]
to a set of similar benchmarks.
.BU "I/O (disk) benchmarks" :
IOstone
.RN Park90 
wants to be an I/O benchmark, but actually measures the memory
subsystem; all of the tests fit easily in the cache.
IObench
.RN Wolman89 
is a systematic file system and disk benchmark, but it is 
complicated and unwieldy.
In
.RN McVoy91 
we reviewed many I/O benchmarks and found them all
lacking because they took too long to run and 
were too complex a solution to a fairly simple problem.  We wrote a 
small, simple I/O benchmark, \*[lmdd] that
measures sequential and random I/O far 
faster than either IOstone or IObench.  As part of 
.RN McVoy91
the results from \*[lmdd] were checked against IObench (as well as some other
Sun internal I/O benchmarks).   \*[lmdd] proved to be more accurate than any
of the other benchmarks.
At least one disk vendor
routinely uses \*[lmdd] to do performance testing of its disk drives.
.SP
Chen and Patterson
.RN "Chen93, Chen94"
measure I/O performance under a
variety of workloads that are automatically varied to test the
range of the system's performance.  
Our efforts differ in that we are more interested in the CPU overhead
of a single request, rather than the capacity of the system as a whole.
.BU "Berkeley Software Distribution's microbench suite" :
The BSD effort generated an extensive set of 
test benchmarks to do regression testing (both quality and performance)
of the BSD releases.  
We did not use this as a basis for our work (although we used ideas)
for the following reasons:
(a) missing tests \(em such as memory latency,
(b) too many tests, the results tended to be obscured under a mountain
of numbers,
and (c) wrong copyright \(em we wanted the
Free Software Foundation's General Public License.
.BU "Ousterhout's Operating System benchmark" :
.RN Ousterhout90
proposes several system benchmarks to measure system call
latency, context switch time, and file system performance.
We used the same ideas as a basis for our work,  while trying to
go farther.  We measured a more complete set of
primitives, including some hardware measurements; went into greater depth
on some of the tests, such as context switching; and went to great
lengths to make the benchmark portable and extensible.
.BU "Networking benchmarks" :
\f(CWNetperf\fP measures networking bandwidth and latency and 
was written by Rick Jones of Hewlett-Packard.
\*[lmbench] includes a smaller,
less complex benchmark that produces similar results.
.SP
\f(CWttcp\fP is a widely used benchmark in the Internet community.  
Our version of the same benchmark 
routinely delivers bandwidth numbers that are within 2% of the numbers 
quoted by \f(CWttcp\fP.
.BU "McCalpin's stream benchmark" :
.RN McCalpin95
has memory bandwidth measurements and results for a large number of
high-end systems.  
We did not use these because we discovered them only after
we had results using our versions.
We will probably include McCalpin's benchmarks in \*[lmbench]
in the future.
.PP
In summary, we rolled our own because we wanted simple, portable
benchmarks that accurately measured a wide variety of operations that we
consider crucial to performance on today's systems.  While portions of
other benchmark suites include similar work, none includes all of it,
few are as portable, and almost all are far more complex.  Less filling,
tastes great.
.NH 1
Benchmarking notes
.NH 2
Sizing the benchmarks
.PP
The proper sizing of various benchmark parameters is crucial to ensure
that the benchmark is measuring the right component of system performance.  
For example, memory-to-memory copy
speeds are dramatically affected by the location of the data: if
the size parameter is too small so
the data is in a cache, then the performance may be as much as ten times
faster than if the data is in memory.
On the other hand, if the memory size parameter is too big so the data
is paged to disk, then performance may be slowed to such an extent
that the benchmark seems to `never finish.'
.PP
\*[lmbench] takes the following approach to the cache and memory
size issues:
.BU
All of the benchmarks that could be affected
by cache size are run in a loop,
with increasing sizes (typically powers of two) until some maximum size
is reached.  The results may then be plotted to see where the benchmark
no longer fits in the cache.
.BU
The benchmark verifies that there is sufficient memory to run all of the
benchmarks in main memory.  A small test program allocates as much memory
as it can, clears the memory,
and then strides through that memory a page at a time, timing
each reference.  If any reference takes more than a few microseconds, the
page is no longer in memory.  The test program starts small and works forward
until either enough memory is seen as present or the memory limit is reached.
.NH 2
Compile time issues
.PP
The GNU C compiler, \*[gcc], is the compiler we chose because 
it gave the most reproducible results across platforms.  
When \*[gcc] was not present, we used the vendor-supplied \f(CWcc\fP.
All of the benchmarks were compiled with optimization \f(CW-O\fP
except 
the benchmarks that calculate clock speed and the context switch times,
which must be compiled without optimization in order to produce
correct results.  No other optimization flags were enabled because
we wanted results that would be commonly seen by application writers.
.PP
All of the benchmarks were linked using the default manner of
the target system.  For most if not all systems, the
binaries were linked using shared libraries.   
.NH 2
Multiprocessor issues
.PP
All of the multiprocessor systems ran the benchmarks in the same way as
the uniprocessor systems.  Some systems allow users to pin processes
to a particular CPU, which sometimes results in better cache reuse.  We
do not pin processes because it defeats the MP scheduler.
.\" XXX - I should do this on an IP19 and mark it as pinned.
In certain cases, this decision yields interesting results discussed later.
.NH 2
Timing issues
.LP
.sp -.5
.BU "Clock resolution" :
The benchmarks measure the elapsed time by reading the system clock via the
\*[gettimeofday] interface.  On some systems this interface has a resolution
of 10 milliseconds, a long time relative to many of the benchmarks which
have results measured in tens to hundreds of microseconds.  To compensate for 
the coarse clock resolution, the benchmarks are hand-tuned to measure
many operations within a single time interval lasting for many clock ticks.
Typically, this is done by executing the operation in a small loop, sometimes
unrolled if the operation is exceedingly fast, and then dividing 
the loop time by the loop count.  
.BU Caching :
If the benchmark expects the data to be in the cache, the benchmark is 
typically run several times; only the last result is recorded. 
.SP
If the benchmark does not want to measure cache performance it sets
the size parameter larger than the cache.  For example, the
\*[bcopy] benchmark by default copies 8 megabytes to 8 megabytes,
which largely defeats any second-level cache in use today.  (Note that the 
benchmarks are not trying to defeat the file or process page cache,
only the hardware caches.)
.br
.di bigtable
.ev keep
.ps 8
.vs 9
.so systems.tbl
.ps \n[PS]
.vs \n[VS]
.nr TABLE \n[TABLE]+1
.ce 1
.SP
\fBTable \n[TABLE].\ \ System descriptions.\fP
.SP
.di
.ev
.nr WHEN \n[dn]+\n[FM]
.nr THT \n[dn]
.de print*table
'	sp .5
'	ev keep
'	nf
'	bigtable
.	ne 1
.	wh -\n[WHEN]u skip*page
.	fi
.	ev
..
.de skip*page
'	sp \n[THT]u
.	wh -\n[WHEN]u
..
.wh -\n[WHEN]u print*table
.BU Variability :
The results of some benchmarks, most notably the context switch benchmark, had a tendency
to vary quite a bit, up to 30%.  We suspect that the
operating system is not using the same set of physical
pages each time a process is created and we are seeing the effects of
collisions in the external caches.  We compensate by running the 
benchmark in a loop and taking the minimum result.  Users interested in
the most accurate data are advised to verify the results on their
own platforms.
.PP
Many of the results included in the database were donated by users
and were not created by the authors.
Good benchmarking practice suggests that one should run the benchmarks
as the only user of a machine, without other resource intensive
or unpredictable processes or daemons.
.NH 2
Using the \f(CBlmbench\fP database
.PP
\*[lmbench] includes a database of results that
is useful for comparison purposes.  It is quite easy to
build the source, run the benchmark, and produce a table of results
that includes the run.  All of the tables in this paper were produced
from the database included in \*[lmbench].  This paper is also
included with \*[lmbench] and may be reproduced incorporating new results.
For more information, consult the file \f(CWlmbench-HOWTO\fP in the 
\*[lmbench] distribution.
.NH 1
Systems tested
.PP
\*[lmbench] has been run on a wide variety of platforms. This
paper includes results from a representative subset of machines and
operating systems.
Comparisons between similar hardware running different operating
systems can be very illuminating, and we have included a few examples
in our results.
.PP
The systems are briefly characterized in Table 1.  Please note that the list prices
are very approximate as is the year of introduction.
The SPECInt92 numbers are a little suspect since 
some vendors have been ``optimizing'' for certain parts of SPEC.  We try and
quote the original SPECInt92 numbers where we can.
.NH 2
Reading the result tables
.PP
Throughout the rest of this paper, we present tables of results for many of the
benchmarks.  All of the tables are sorted, from best to worst.  Some tables
have multiple columns of results and those tables are sorted on only one of
the columns.  The sorted column's heading will be in \fBbold\fP.
.NH 1
Bandwidth benchmarks
.PP
By bandwidth, we mean the rate at which a particular facility can move
data.  
We attempt to measure the data movement ability of a number of
different facilities:
library \*[bcopy],
hand-unrolled \*[bcopy],
direct-memory read and write (no copying),
pipes,
TCP sockets,
the \*[read] interface,
and
the \*[mmap] interface.
.NH 2
Memory bandwidth
.PP
Data movement is fundamental to any operating system.  
In the past, performance
was frequently measured in MFLOPS because floating point units were
slow enough that microprocessor systems were
rarely limited by memory bandwidth.  Today, floating point units are usually much
faster than memory bandwidth, so many current MFLOP ratings can not be 
maintained using memory-resident data; they are ``cache only'' ratings.
.PP
We measure the ability to
copy, read, and write data over a varying set of sizes.
There are too many results to report all of them here, so we concentrate on 
large memory transfers.
.PP
We measure copy bandwidth two ways.  The first is the user-level library
\*[bcopy] interface.
The second is a hand-unrolled loop that loads and stores
aligned 8-byte words.  
In both cases, we took care to
ensure that the source and destination locations would not map to the same
lines if the any of the caches were direct-mapped.  
In order to test memory bandwidth rather than cache bandwidth, 
both benchmarks copy an 8M\** area to another 8M area.  
(As secondary caches reach 16M, these benchmarks will have to
be resized to reduce caching effects.)
.FS
Some of the PCs had less than 16M of available memory;
those machines copied 4M. 
.FE
.PP
The copy results actually represent one-half to one-third of the memory
bandwidth used to obtain those results since we are reading and writing
memory.  If the cache line size is larger than the word stored, then
the written cache line will typically be read before it is written.  The
actual amount of memory bandwidth used varies because some architectures
have special instructions specifically designed for the \*[bcopy]
function.  Those architectures will move twice as much memory as
reported by this benchmark; less advanced architectures move three
times as much memory: the memory read, the memory read because it is
about to be overwritten, and the memory written.
.PP
The \*[bcopy] results reported in Table 2
may be correlated with John McCalpin's \*[stream]
.RN McCalpin95
benchmark results in the following manner:
the \*[stream] benchmark reports all of the memory moved
whereas the \*[bcopy] benchmark reports the bytes copied.  So our
numbers should be approximately one-half to one-third of his numbers.
.PP
Memory reading is measured by an unrolled loop that sums up a series of
integers.  On most (perhaps all) systems measured the integer
size is 4 bytes.  The loop is unrolled such that most compilers generate
code that uses a constant offset with the load, resulting in a load and
an add for each word of memory.  The add is an integer add that completes
in one cycle on all of the processors.  Given that today's processor 
typically cycles at 10 or fewer nanoseconds (ns) and that memory is typically 200-1,000
ns per cache line, the results reported here should be dominated by the
memory subsystem, not the processor add unit.
.PP
The memory contents are added up because almost all C compilers
would optimize out the whole loop when optimization was turned on, and
would generate far too many instructions without optimization.
The solution is to
add up the data and pass the result as an unused argument to the 
``finish timing'' function.  
.PP
Memory reads represent about one-third to one-half of the \*[bcopy] work, and we expect
that pure reads should run at roughly twice the speed of \*[bcopy].
Exceptions to this rule should be studied, for exceptions indicate a bug
in the benchmarks, a problem in \*[bcopy], or some unusual hardware.  
.TSTART
.so ../Results/tmp/bw_allmem.tbl
.TEND "Memory bandwidth (MB/s)"
.PP
Memory writing is measured by an unrolled loop that stores a value into
an integer (typically a 4 byte integer) and then increments the pointer.
The processor cost of each memory operation is approximately the same
as the cost in the read case.
.PP
The numbers reported in Table \n[TABLE]
are not the raw hardware speed in some cases.
The Power2\** is capable of up to 800M/sec read rates 
.FS
Someone described this machine as a $1,000 processor on a $99,000 memory
subsystem.
.FE
.RN McCalpin95
and HP PA RISC (and other prefetching)
systems also do better if higher levels of code optimization used
and/or the code is hand tuned.
.PP
The Sun libc bcopy in Table \n[TABLE] 
is better because they use a hardware specific bcopy
routine that uses instructions new in SPARC V9 that were added specifically
for memory movement.
.PP
The Pentium Pro read rate in Table \n[TABLE] is much higher than the write rate because,
according to Intel, the write transaction turns into a read followed by
a write to maintain cache consistency for MP systems.
.NH 2
IPC bandwidth
.PP
Interprocess communication bandwidth is frequently a performance issue.
Many Unix applications are composed of several processes communicating
through pipes or TCP sockets.  Examples include the \f(CWgroff\fP documentation
system that prepared this paper, the \f(CWX Window System\fP, remote file access,
and \f(CWWorld Wide Web\fP servers.
.PP
Unix pipes are an interprocess communication mechanism implemented as 
a one-way byte stream. Each end of the stream has an associated file
descriptor; one is the write descriptor and the other the read
descriptor.
TCP sockets are similar
to pipes except they are bidirectional and can cross machine 
boundaries.
.PP
Pipe bandwidth is measured by creating two processes, a writer and a
reader, which transfer 50M of data in 64K transfers.
The transfer size was chosen so that the overhead of system calls
and context switching would not dominate the benchmark time.
The reader prints the timing results, which guarantees that all
data has been moved before the timing is finished.
.PP
TCP bandwidth is measured similarly, except the data is transferred in
1M page aligned transfers instead of 64K transfers.  If the TCP
implementation supports it, the send and receive socket buffers are
enlarged to 1M, instead of the default 4-60K.  We have found that
setting the transfer size equal to the socket buffer size produces the
greatest throughput over the most implementations.
.TSTART
.so ../Results/tmp/bw_ipc.tbl
.TEND "Pipe and local TCP bandwidth (MB/s)"
.PP
\*[bcopy] is important to this test because the 
pipe write/read is typically implemented as a \*[bcopy] into the kernel
from the writer and then a \*[bcopy] from the kernel to the reader.  
Ideally, these results would be approximately one-half of the 
\*[bcopy] results.  It is possible for the kernel \*[bcopy]
to be faster than the C library \*[bcopy] since the kernel may have 
access to \*[bcopy] hardware unavailable to the C library.
.PP
It is interesting to compare pipes with TCP because the TCP benchmark is
identical to the pipe benchmark except for the transport mechanism.  
Ideally, the TCP bandwidth would be as good as the pipe
bandwidth.  It is not widely known that the
majority of the TCP cost is in the \*[bcopy], the checksum,
and the network interface driver. 
The checksum and the driver may be safely eliminated in the loopback
case and if the costs have been eliminated, then TCP should be just as
fast as pipes.  From the pipe and TCP results in Table \n[TABLE], it is easy to
see that Solaris and HP-UX have done this optimization.
.PP
Bcopy rates in Table \n[TABLE] can be lower than pipe rates because the
pipe transfers are done in 64K buffers, a size that frequently fits in
caches, while the bcopy is typically an 8M-to-8M copy, which does not
fit in the cache.
.PP
In Table \n[TABLE], the SGI Indigo2, a uniprocessor, does better than
the SGI MP on pipe bandwidth because of caching effects - in the UP
case, both processes share the cache; on the MP, each process is
communicating with a different cache.
.PP
All of the TCP results in Table \n[TABLE] are in loopback mode \(em that
is both ends of the socket are on the same machine.  It was impossible
to get remote networking results for all the machines included in this
paper.  We are interested in receiving more results for identical
machines with a dedicated network connecting them.  The results we have
for over the wire TCP bandwidth are shown below.
.TSTART
.so tcp_bw.tbl
.TEND "Remote TCP bandwidth (MB/s)"
.PP
The SGI using 100MB/s Hippi is by far the fastest in Table \n[TABLE].
The SGI Hippi interface has hardware support for TCP checksums and 
the IRIX operating system uses virtual memory tricks to avoid copying 
data as much as possible.
For larger transfers, SGI Hippi has reached 92MB/s over TCP.
.PP
100baseT is looking quite competitive when compared to FDDI in Table
\n[TABLE], even though FDDI has packets that are almost three times
larger.  We wonder how long it will be before we see gigabit ethernet
interfaces.
.NH 2
Cached I/O bandwidth
.PP
Experience has shown us that reusing data in the file system
page cache can be a performance issue.  This 
section measures that operation through two interfaces, \*[read] and
\*[mmap].   
The benchmark here is not an I/O benchmark in that no disk activity is
involved.
We wanted to measure the overhead
of reusing data, an overhead that is CPU intensive, rather than disk intensive.
.PP
The \*[read] interface copies data from the kernel's file system page cache into the
process's buffer, using 64K buffers.  The transfer size was chosen 
to minimize the kernel entry overhead while
remaining realistically sized.
.PP
The difference between the \*[bcopy] and the \*[read] benchmarks
is the cost of the file and virtual memory system overhead.  In most
systems, the \*[bcopy] speed should be faster than the \*[read] speed.  The
exceptions usually have hardware specifically designed
for the \*[bcopy] function and that hardware may be available only to
the operating system.  
.PP
The \*[read] benchmark is implemented by rereading a file
(typically 8M) in 64K
buffers.  Each buffer is summed as a series of integers in the user
process.  The summing is done for two reasons: for an apples-to-apples
comparison the memory-mapped benchmark needs to touch all the data,
and the file system can sometimes transfer data into memory faster than the
processor can read the data.
For example, \s-1SGI\s0's XFS can move data into memory at
rates in excess of 500M per second, but it can move data into
the cache at only 68M per second.  The intent is to measure performance
delivered to the application, not DMA performance to memory.
.TSTART
.so ../Results/tmp/bw_reread2.tbl
.TEND "File vs. memory bandwidth (MB/s)"
.PP
The \*[mmap] interface provides a way to access the kernel's file cache 
without copying the data.  
The \*[mmap] benchmark is implemented by mapping the entire file (typically 8M)
into the
process's address space.  The file is then summed to force the data
into the cache.
.PP
In Table \n[TABLE], 
a good system will have \fIFile read\fP as fast as (or even faster than)
\fILibc bcopy\fP because as the file system overhead goes to zero, the
file reread case is virtually the same as the library \*[bcopy] case.
However, file reread can be faster because the kernel may have access to
\*[bcopy] assist hardware not available to the C library.  
Ideally, \fIFile mmap\fP performance should approach \fIMemory read\fP
performance, but \*[mmap] is often dramatically worse.  
Judging by the results, this looks to be a 
potential area for operating system improvements.
.PP
In Table \n[TABLE] the Power2 does better on file reread than bcopy because it takes
full advantage of the memory subsystem from inside the kernel.  
The mmap reread is probably slower because of the lower clock rate;
the page faults start to show up as a significant cost.   
.PP
It is surprising that the Sun Ultra1 was able to bcopy at the high
rates shown in Table 2 but did not show those rates for file reread
in Table \n[TABLE].
HP has the opposite problem, they get file reread faster than bcopy,
perhaps because the kernel \*[bcopy] has access to hardware support.
.PP
The Unixware system has outstanding mmap reread rates, better than
systems of substantially higher cost.  Linux needs to do some work on
the \f(CWmmap\fP code.
.NH 1
Latency measurements
.PP
Latency is an often-overlooked
area of performance problems, possibly because resolving latency issues
is frequently much harder than resolving bandwidth issues.  For example,
memory bandwidth may be increased by making wider cache lines and increasing
memory ``width'' and interleave,
but memory latency can be improved only by shortening paths or increasing
(successful) prefetching.  
The first step toward improving latency is understanding the 
current latencies in a system.
.PP
The latency measurements included in this suite are
memory latency,
basic operating system entry cost,
signal handling cost,
process creation times,
context switching,
interprocess communication,
.\" virtual memory system latency,
file system latency, 
and disk latency.
.NH 2 
Memory read latency background
.PP
In this section, we expend considerable effort to define the different memory
latencies and to explain and justify our benchmark.
The background is a bit tedious but important, since we believe the
memory
latency measurements to be one of the most thought-provoking and useful
measurements in \*[lmbench].  
.PP
The most basic latency measurement is memory latency since most of
the other latency measurements can be expressed in terms of memory
latency.  For example, context switches require saving the current
process state and loading the state of the next process.  However, memory
latency is rarely accurately measured and frequently misunderstood.
.PP
Memory read latency has many definitions;
the most common,
in increasing time order,
are memory chip cycle time, processor-pins-to-memory-and-back time,
load-in-a-vacuum time, and back-to-back-load time.  
.BU "Memory chip cycle latency" :
Memory chips are rated in nanoseconds; typical speeds are around 60ns.
A general overview on DRAM architecture may be found in
.RN Hennessy96 .
The 
specific information we describe here is from 
.RN Toshiba94  
and pertains to the \s-1THM361020AS-60\s0 module and \s-1TC514400AJS\s0
\s-1DRAM\s0 used in \s-1SGI\s0 workstations.  The 60ns time is the
time from 
.ps -1
.nr width \w'R\&A\&S'
.nr height \n[rst]+1000
RAS\v'-\n[height]u'\h'-\n[width]u'\fB\l'\n[width]u'\fP\v'\n[height]u'
.ps
assertion to the when 
the data will be available on the \s-1DRAM\s0 pins (assuming 
.ps -1
.nr width \w'C\&A\&S'
.nr height \n[rst]+1000
CAS\v'-\n[height]u'\h'-\n[width]u'\fB\l'\n[width]u'\fP\v'\n[height]u'
.ps
access time requirements were met).
While it is possible
to get data out of a \s-1DRAM\s0 in 60ns, that is not all of
the time involved.  There is a precharge time that must occur after
every access.
.RN Toshiba94
quotes 110ns as the random read or write cycle time and this
time is more representative of the cycle time.  
.\" For example, most systems offer a wide range of memory 
.\" capacity, from 64MB to 1GB or more.  If 64MB simms are used, the number
.\" of simms range from 1 to 16.  The more simms there are, the more 
.\" capacitance there is in the memory subsystem.  More capacitance means
.\" longer setup times for the fully populated memory subsystem.  System
.\" designers have to allow time for this setup.
.\" For more details, consult [XXX - reference on DRAM].
.\" This is sometimes referred to as the chip latency.  The
.\" chip cycle time is the chip latency plus the time required to restore
.\" the data in the capacitors which is often referred to as the precharge
.\" time.  This means that 60 nanosecond memory chips really are more like
.\" 100 nanosecond memory chips.  Some systems operate memory in ``page
.\" mode'' or ``static column'' memory systems hold either RAS or CAS and
.\" allow subsequent accesses in the same row or column in one cycle instead
.\" of two.
.BU "Pin-to-pin latency" :
This number represents the time needed
for the memory request to travel from the processor's pins to the memory
subsystem and back again.  Many vendors have used the pin-to-pin
definition of memory latency in their reports.  For example, 
.RN Fenwick95 
while describing the \s-1DEC\s0 8400
quotes memory latencies of 265ns; a careful
reading of that paper shows that these are pin-to-pin numbers.  In spite
of the historical precedent in vendor reports, this definition of memory
latency is misleading since it ignores actual delays seen when a load
instruction is immediately followed by a use of the data being loaded.
The number of additional cycles inside the processor can be significant
and grows more significant with today's highly pipelined architectures.
.PP
It is worth noting that the pin-to-pin numbers 
include the amount of time it takes to charge
the lines going to the \s-1SIMM\s0s, a time that increases with the
(potential) number of \s-1SIMM\s0s in a system.  More \s-1SIMM\s0s mean
more capacitance which requires in longer charge times.  This is one reason
why personal computers frequently have better memory latencies than
workstations: the PCs typically have less memory capacity.
.BU "Load-in-a-vacuum latency" :
A load in a vacuum is the time that the processor will wait for one load that
must be fetched from main memory (i.e., a cache miss).  The ``vacuum'' 
means that there is no other activity on the system bus, including no other
loads.  
While this number is frequently used as the memory latency, it is not very
useful.  It is basically a ``not to exceed'' number important only for
marketing reasons.
Some architects point out that since most processors implement nonblocking
loads (the load does not cause a stall until the data is used), the perceived
load latency may be much less that the real latency.  When pressed, however,
most will admit that cache misses occur in bursts, resulting in perceived
latencies of at least the load-in-a-vacuum latency.
.BU "Back-to-back-load latency" :
Back-to-back-load latency is the time that each load takes, assuming
that the instructions before and after are also cache-missing loads.
Back-to-back loads may take longer than loads in a vacuum for the
following reason: many systems implement something known as \fIcritical
word first\fP, which means that the subblock of the cache line that
contains the word being loaded is delivered to the processor before the
entire cache line has been brought into the cache.  If another load
occurs quickly enough after the processor gets restarted from the
current load, the second load may stall because the cache is still
busy filling the cache line for the previous load.  On some systems,
such as the current implementation of UltraSPARC, 
the difference between back to back and load in a vacuum is about 35%.
.PP
\*[lmbench] measures back-to-back-load latency because it is the
only measurement that may be easily measured from software and
because we feel that it is what most software developers consider to be memory
latency.  Consider the following C code fragment:
.DS
.nf
.ft CW
p = head;
while (p->p_next)
	p = p->p_next;
.ft
.fi
.DE
On a \s-1DEC\s0 Alpha, the loop part turns into three instructions, including the
load.  A 300 Mhz processor has a 3.33ns cycle time, so the loop
could execute in slightly less than 10ns.  However, the load itself
takes 400ns on a 300 Mhz \s-1DEC\s0 8400.  In other words, the 
instructions cost 10ns but the load stalls for 400.  Another
way to look at it is that 400/3.3, or 121, nondependent,
nonloading instructions following the load would be needed 
to hide the load latency.  
Because superscalar processors typically execute multiple operations
per clock cycle, they need even more useful operations between cache
misses to keep the processor from stalling.
.PP
This benchmark illuminates the tradeoffs in processor cache design.
Architects like large cache lines, up to 64 bytes or so, because 
the prefetch effect of gathering a whole line increases
hit rate given reasonable spatial locality.
Small stride sizes have high spatial locality and should have higher
performance, but large stride sizes have poor spatial locality causing
the system to prefetch useless data.
So the benchmark provides the following insight into negative 
effects of large line prefetch:
.BU 
Multi-cycle fill operations are typically atomic events at the 
caches, and sometimes block other cache accesses until they
complete.
.BU
Caches are typically single-ported. Having a large line prefetch
of unused data causes extra bandwidth
demands at the cache, and can cause increased access latency for 
normal cache accesses.
.PP
In summary, we believe that processors are so fast that the average
load latency for cache misses will be closer to the
back-to-back-load number than to the load-in-a-vacuum number.  We are
hopeful that the industry will standardize on this definition of
memory latency.
.NH 2 
Memory read latency
.PP
The entire memory hierarchy can be measured, including on-board data 
cache latency and size, external data cache latency and size, and 
main memory latency.
Instruction caches are not measured.
TLB miss latency can also be measured, as in 
.RN Saavedra92 ,
but we stopped at main memory.  Measuring TLB miss time is problematic
because different systems map different amounts of memory with their 
TLB hardware.
.PP
The benchmark varies two parameters, array size and array stride.  
For each size, a list of pointers is created for all of the different 
strides.  Then the list is walked thus:
.DS
.ft CW
mov  r4,(r4)  # C code: p = *p;
.ft
.DE
The time to do about 1,000,000 loads (the list wraps) is measured and
reported.  The time reported is pure latency time and may be zero even though
the load instruction does not execute in zero time.  Zero is defined as one
clock cycle; in other words, the time reported is \fBonly\fP memory latency
time, as it does not include the instruction execution time.  It is assumed
that all processors can do a load instruction in one processor cycle 
(not counting stalls).  In other words, if the processor cache load time
is 60ns on a 20ns processor, the load latency reported
would be 40ns, the additional 20ns is for the load instruction
itself.\**
.FS
In retrospect, this was a bad idea because we calculate the clock
rate to get the instruction execution time.  If the clock rate is off,
so is the load time.
.FE
Processors that can manage to get the load address out to the 
address pins before the end of the load cycle get some free time in this
benchmark (we don't know of any processors that do that).
.PP
This benchmark has been validated by logic analyzer measurements
on an \s-1SGI\s0 Indy by Ron Minnich while he was at the Maryland Supercomputer
Research Center.
.TSTART 1
.so mem.pic
.FEND "Memory latency" 1
.PP
Results from the memory latency benchmark are plotted as a series of data sets
as shown in Figure \n[FIGURE].
Each data set represents a stride size,
with the array size varying from 512 bytes up to 8M or more.
The curves contain a series of 
horizontal plateaus, where each plateau represents a level in the
memory hierarchy.  
The point where each plateau ends and the line rises marks the
end of that portion of the memory hierarchy (e.g., external cache).  
Most machines have similar memory hierarchies:
on-board cache, external cache, main memory, and main memory plus TLB
miss costs.  
There are variations: some processors are missing a cache, while 
others add another cache to the hierarchy.
.\" XXX Larry please double-check this; I am going on dim memory...
For example, the Alpha 8400 has two on-board caches, one 8K
and the other 96K.
.PP
The cache line size can be derived by comparing curves and noticing which
strides are faster than main memory times.  The smallest stride that is
the same as main memory speed is likely to be the cache line size because
the strides that are faster than memory are
getting more than one hit per cache line.  
.\" Prefetching may confuse
.\" the issue because a demand read may stall behind a prefetch load,
.\" causing cache lines to appear twice as large as they are.
.\" XXX
.\" Larry --- can we use prime modulus arithmetic to set up pointer 
.\" loops which might appear random but which really aren't and which
.\" hit every stride once before looping?
.\"
.\" XXX
.\" Larry --- is there any way we can defeat/disable prefetching
.\" so the cache line size can be more accurately determined?
.\"
.\" XXX
.\" Larry --- can we create a benchmark for TLB misses?
.\" I think it was Tom Rokicki who suggested that we create a
.\" benchmark where the data fits in the cache, but the pages don't
.\" fit in the TLB.  
.\"
.\" XXX
.\" Larry --- is the description of the memory hierarchy correct?
.\" I am not sure I haven't added an extra level of external cache...
.EQ
delim $$
.EN
.PP
Figure \n[FIGURE] shows memory latencies on a nicely made machine,
a \s-1DEC\s0 Alpha.
We use this machine as the example 
because it shows the latencies and sizes of
the on-chip level 1 and motherboard level 2 caches, and because it
has good all-around numbers, especially considering it can support a
4M level 2 cache.
The on-board cache is $2 sup 13$ bytes or 8K, while the
external cache is $2 sup 19$ bytes or 512K.
.EQ
delim off
.EN
.TSTART
.so lat_allmem.tbl
.TEND "Cache and memory latency (ns)"
.nr MEMTABLE \n[TABLE]
.PP
Table \n[TABLE] shows the cache size, cache latency, and main memory
latency as extracted from the memory latency graphs.  
The graphs and the tools for extracting the data are 
included with \*[lmbench].  
It is worthwhile to plot all of the graphs and examine them since the
table is missing some details, such as the
\s-1DEC\s0 Alpha 8400 processor's second 96K on-chip cache.
.PP
We sorted Table \n[TABLE] on level 2 cache latency because we think
that many applications will fit in the level 2 cache.  The HP and IBM
systems have only one level of cache so we count that as both level 1
and level 2.  Those two systems have remarkable cache performance for
caches of that size.  In both cases, the cache delivers data in one
clock cycle after the load instruction.  
.PP
HP systems usually focus on
large caches as close as possible to the processor.  A older HP
multiprocessor system, the 9000/890, has a 4M, split I&D, direct mapped
cache with a 2K victim cache, accessible in one clock (16ns).\**  That system is
primarily a database server.  
.FS
The Usenix version of this paper had this as a set associate cache; that was
incorrect.
.FE
.PP
The IBM focus is on low latency, high
bandwidth memory.  The IBM memory subsystem is good because all of
memory is close to the processor, but has the weakness that it is
extremely difficult to evolve the design to a multiprocessor system.
.PP 
The 586 and PowerPC motherboards have quite poor second level caches,  
the caches are not substantially better than main memory.
.PP
The Pentium Pro and Sun Ultra second level caches are of medium speed 
at 5-6 clocks latency each.  5-6 clocks seems fast until it is compared
against the HP and IBM one cycle latency caches of similar size.  
Given the tight integration of the Pentium Pro level 2 cache, it is 
surprising that it has such high latencies.
.PP
The 300Mhz DEC Alpha has a rather high 22 clock latency to the second
level cache which is probably one of the reasons that they needed a 96K
level 1.5 cache.  SGI and DEC have used large second level caches
to hide their long latency from main memory.
.PP
.NH 2
Operating system entry
.PP
Entry into the operating system is required for many system facilities.  
When calculating the cost of a facility, it is useful to know how
expensive it is to perform a nontrivial entry into the operating system.
.PP
We measure nontrivial entry into the system by repeatedly writing one
word to \f(CW/dev/null\fP, a pseudo device driver that does nothing but
discard the data.   This particular entry point was chosen because it has
never been optimized in any system that we have measured.  Other entry
points, typically \*[getpid] and \*[gettimeofday], are heavily used,
heavily optimized, and sometimes implemented as user-level library
routines rather than system calls.  
A write to the \f(CW/dev/null\fP driver will go
through the system call table to \*[write], verify the user area as
readable, look up the file descriptor to get the vnode, call the vnode's
write function, and then return.  
.TSTART
.so ../Results/tmp/lat_nullsys.tbl
.TEND "Simple system call time (microseconds)"
.PP
Linux is the clear winner in the system call time.  The reasons are
twofold: Linux is a uniprocessor operating system, without any
MP overhead, and Linux is a small operating system, without all
of the ``features'' accumulated by the commercial offers.
.PP
Unixware and Solaris are doing quite well, given that they are both fairly
large, commercially oriented operating systems with a large accumulation
of ``features.''
.NH 2
Signal handling cost
.PP
Signals in Unix are a way to tell another process to handle an event.  They
are to processes as interrupts are to the CPU.
.PP
Signal handling is often critical to layered systems.  Some applications,
such as databases, software development environments, and threading libraries
provide an operating system-like layer on top of the operating system,
making signal handling a critical path in many of these applications.
.PP
\*[lmbench] measure both signal installation and signal dispatching in two separate
loops, within the context of one process.
It measures signal handling by installing a signal handler and then repeatedly
sending itself the signal.   
.TSTART
.so ../Results/tmp/lat_signal.tbl
.TEND "Signal times (microseconds)"
.PP
Table \n[TABLE] shows the signal handling costs.  
Note that there are no context switches in this benchmark; the signal goes
to the same process that generated the signal.  In real applications,
the signals usually go to another process, which implies
that the true cost of sending that signal is the signal overhead plus the
context switch overhead.  We wanted to measure signal and context
switch overheads separately since context
switch times vary widely among operating systems.
.PP
SGI does very well on signal processing,
especially since their hardware is of an older generation than
many of the others.  
.PP
The Linux/Alpha signal handling numbers are so poor
that we suspect that this is a bug, especially given that the Linux/x86
numbers are quite reasonable.
.NH 2
Process creation costs
.PP
Process benchmarks are used to measure the basic process primitives,
such as creating a new process, running a different program, and context
switching.  Process creation benchmarks are of particular interest
in distributed systems since many remote operations include the creation
of a remote process to shepherd the remote operation to completion.
Context switching is important for the same reasons.
.BU "Simple process creation" .
The Unix process creation primitive is \*[fork], which
creates a (virtually) exact copy of the calling process.
Unlike VMS and some other operating systems, Unix starts any new process
with a \*[fork].  
Consequently, \*[fork] and/or \f(CWexecve\fP should be fast and
``light,'' facts that many have been ignoring for some time.
.PP
\*[lmbench] measures simple process creation by creating a process 
and immediately
exiting the child process.  The parent process waits for the child
process to exit.   
The benchmark is intended to measure the overhead for creating a 
new thread of control, so it includes the \*[fork] and
the \*[exit] time.
.PP
The benchmark also includes a \f(CWwait\fP system call in the parent and
context switches from the parent to the child and back again.   Given that
context switches of this sort are on the order of 20 microseconds and a 
system call is on the order of 5 microseconds, and that the entire benchmark
time is on the order of a millisecond or more, the extra overhead
is insignificant.
Note that even this relatively simple task is very expensive and is
measured in milliseconds while most of the other operations we consider are
measured in microseconds.  
.BU "New process creation" .
The preceding benchmark did not create a new application; it created a
copy of the old application.   This benchmark measures the cost of creating a
new process and changing that process into a new application, which.  
forms the basis of every Unix command
line interface, or shell.  
\*[lmbench] measures this facility by forking a new child and having that child
execute a new program \(em in this case, a tiny program that prints 
``hello world'' and exits.
.PP
The startup cost is especially noticeable
on (some) systems that have shared libraries.  Shared libraries can
introduce a substantial (tens of milliseconds) startup cost.  
.\" XXX - statically linked example?
.TSTART
.so ../Results/tmp/lat_allproc.tbl
.TEND "Process creation time (milliseconds)"
.BU "Complicated new process creation" .
When programs start other programs, they frequently use one of
three standard interfaces: \*[popen], \*[system], and/or \*[execlp].  The first
two interfaces start a new process by invoking the standard command
interpreter, \f(CW/bin/sh\fP, to start the process.  Starting programs this way
guarantees that the shell will look for the requested application
in all of the places that the user would look \(em in other words, the shell
uses the user's $PATH variable as a list of places to find the
application.  \*[execlp] is a C library routine which also looks for the
program using the user's $PATH variable.
.PP
Since this is a common way of starting applications, we felt it
was useful to show the costs of the generality.
.PP
We measure this by starting \f(CW/bin/sh\fP to start the same tiny 
program we ran in the last case.
In Table \n[TABLE] the cost of asking the shell to go 
look for the program is
quite large, frequently ten times as expensive as just creating a 
new process, and four times as expensive as explicitly naming the location
of the new program.
.PP
The results that stand out in Table \n[TABLE] are the poor Sun Ultra 1 results.
Given that the processor is one of the fastest, the problem is likely to be
software.  There is room for substantial improvement in the Solaris
process creation code.
.NH 2
Context switching
.PP
Context switch time is defined here as 
the time needed to save the state of one process and restore the state
of another process.  
.PP
Context switches are frequently in the critical performance path of 
distributed applications.  For example, the multiprocessor versions
of the IRIX operating system use
processes to move data through the networking stack.  This means that the
processing time for each new packet arriving at an idle system includes
the time needed to switch in the networking process.  
.PP
Typical context switch benchmarks measure just the minimal context switch
time \(em the time to switch between two processes that are doing nothing
but context switching.  We feel that this is
misleading because there are frequently more than two active processes,
and they usually have a larger working set (cache footprint)
than the benchmark processes.
.PP
Other benchmarks frequently include the cost of 
the system calls needed to force the context switches.  
For example, Ousterhout's context switch benchmark 
measures context switch time plus a \*[read] and a \*[write]
on a pipe.  
In many of the systems measured by \*[lmbench], the pipe overhead 
varies between 30% and 300% of the context switch time, so we were 
careful to factor out the pipe overhead.
.BU "Number of processes."
The context switch benchmark is implemented as 
a ring of two to twenty processes that are connected with Unix pipes.  
A token is passed from process to process, forcing context switches.  
The benchmark measures the time needed to pass
the token two thousand times from process to process.  
Each transfer of the token has two costs: the context switch, and
the overhead of passing the token.
In order to calculate just the context switching time, the benchmark first
measures the cost of passing the token through a ring of pipes in a
single process.  This overhead time is defined as the cost of passing
the token and is not included in the reported context switch time.
.BU "Size of processes."
In order to measure more realistic context switch times, we add
an artificial variable size ``cache footprint'' to the switching
processes.  The cost of the context switch then includes the cost
of restoring user-level state (cache footprint).  The cache footprint
is implemented by having the process allocate an array of data\**
.FS
All arrays are at the same virtual
address in all processes.
.FE
and sum
the array as a series of integers after receiving the token but before
passing the token to the next process.  Since most systems will cache data
across context switches, the working set for the benchmark is slightly 
larger than the number of processes times the array size.  
.PP
It is worthwhile to point out that the overhead mentioned above
also includes the cost of accessing the data, in the same way as
the actual benchmark.   However, because the overhead is measured
in a single process, the cost is typically the cost with ``hot''
caches.  In the Figure 2, each size is plotted as a line, with
context switch times on the Y axis, number of processes on the 
X axis, and the process size as the data set.
The process size and the hot cache overhead costs for
the pipe read/writes and any data access is what is labeled
as \f(CWsize=0KB overhead=10\fP.  The size is in kilobytes and the overhead
is in microseconds.
.PP
The context switch time does not include anything other than
the context switch, provided that all the benchmark processes fit in the
cache.  If the total size of all of the benchmark processes is larger
than the cache size,  the cost of each context switch will include cache
misses.
We are trying to show realistic context switch times as a
function of both size and number of processes.
.TSTART 1
.so ctx.pic
.FEND "Context switch times" 1
.PP
Results for an Intel Pentium Pro system running Linux at 167 MHz are
shown in Figure \n[FIGURE].
The data points on the figure are labeled with the working set
due to the sum of data in all of the processes.  The actual working set is
larger, as it includes the process and kernel overhead as well.  
One would expect the context switch times to stay constant until 
the working set is
approximately the size of the second level cache.  The Intel system has a 
256K second level cache, and the context switch times 
stay almost constant until about 256K (marked as .25M in the graph).
.BU "Cache issues"
The context switch benchmark is a deliberate measurement of the
effectiveness of the caches across process context switches.  If the
cache does not include the process identifier (PID, also sometimes
called an address space identifier) as part of the address, then the
cache must be flushed on every context switch.  If the cache does not map
the same virtual addresses from different processes to different cache
lines, then the cache will appear to be flushed on every context
switch.
.PP
If the caches do
not cache across context switches there would be no grouping at the
lower left corner of Figure \n[FIGURE], instead, the graph would
appear as a series of straight, horizontal, parallel lines.  The number
of processes will not matter, the two process case will be just as bad
as the twenty process case since the cache would not be
useful across context switches.
.TSTART
.so ../Results/tmp/ctx.tbl
.TEND "Context switch time (microseconds)"
.PP
We picked four points on the graph and extracted those values for Table
\n[TABLE].  The complete set of values, as well as tools to graph them,
are included with \*[lmbench].
.PP
Note that multiprocessor context switch times are frequently more expensive
than uniprocessor context switch times.  This is because multiprocessor
operating systems tend to have very complicated scheduling code. 
We believe that multiprocessor context switch times can be, and should be,
within 10% of the uniprocessor times.
.PP
Linux does quite well on context switching, especially on the more
recent architectures.  By comparing the Linux 2 0K processes to the
Linux 2 32K processes, it is apparent that there is something wrong
with the Linux/i586 case.  If we look back to Table \n[MEMTABLE], we can
find at least part of the cause.  The second level cache latency for the
i586 is substantially worse than either the i686 or the Alpha.  
.PP
Given the poor second level cache behavior of the PowerPC, it is surprising
that it does so well on context switches, especially the larger sized cases.
.PP
The Sun Ultra1 context switches quite well in part because of enhancements
to the register window handling in SPARC V9.
.NH 2
Interprocess communication latencies
.PP
Interprocess communication latency is important because many operations
are control messages to another process (frequently on another
system).  The time to tell the remote process to
do something is pure overhead and is frequently in the critical path
of important functions such as distributed applications (e.g.,
databases, network servers).
.PP
The interprocess communication latency benchmarks typically have the 
following form: pass a small message (a byte or so) back and forth between two
processes.  The reported results are always the microseconds needed
to do one round trip.  For one way timing, 
about half the round trip is right.  However, the CPU cycles tend to be
somewhat asymmetric for one trip: receiving is typically more
expensive than sending.  
.BU "Pipe latency" .
Unix pipes are an interprocess communication mechanism implemented as 
a one-way byte stream.  Each end of the stream has an associated file
descriptor; one is the write descriptor and the other the read
descriptor.
.PP
Pipes are frequently used as a local IPC mechanism.  Because of the 
simplicity of pipes, they are frequently the fastest portable 
communication mechanism.
.PP
Pipe latency is measured by creating a pair of pipes, forking a child process,
and passing a word back and forth.  This benchmark is identical to the 
two-process, zero-sized context switch benchmark, except that it includes
both the context switching time and the pipe overhead in the results.
.nr NTABLE \n[TABLE]+1
.nr LTABLE \n[TABLE]
Table \n[NTABLE] shows the round trip latency from process A to process B
and back to process A.
.TSTART
.so ../Results/tmp/lat_pipe.tbl
.TEND "Pipe latency (microseconds)"
.PP
The time can be broken down to two context switches plus four system calls
plus the pipe overhead.  The context switch component is two of the small
processes in Table \n[LTABLE].
This benchmark is identical to the context switch benchmark in
.RN Ousterhout90 .
.BU "TCP and RPC/TCP latency" .
TCP sockets may be viewed as an interprocess communication mechanism similar
to pipes with the added feature that TCP sockets work across machine 
boundaries.
.PP
TCP and RPC/TCP connections are frequently used in low-bandwidth, 
latency-sensitive applications.  The default Oracle distributed 
lock manager uses TCP sockets, and the locks per second available 
from this service are accurately modeled by the TCP latency test.
.TSTART
.so ../Results/tmp/lat_tcp.tbl
.TEND "TCP latency (microseconds)"
.PP
Sun's RPC is layered either over TCP or over UDP.
The RPC layer is responsible for managing connections (the port mapper), 
managing different byte orders and word sizes (XDR), and implementing a 
remote procedure call abstraction.
Table \n[TABLE] shows the same benchmark with and
without the RPC layer to show the cost of the RPC implementation.
.PP
TCP latency is measured by having a server process that waits for connections
and a client process that connects to the server.  The two processes then
exchange a word between them in a loop.  The latency reported is one 
round-trip time.  The measurements in Table \n[TABLE] are local 
or loopback measurements, 
since our intent is to show the overhead of the software.  The same benchmark
may be, and frequently is, used to measure host-to-host latency.
.PP
Note that the RPC layer frequently adds hundreds of microseconds of
additional latency.  The problem is not the external data
representation (XDR) layer \(em the
data being passed back and forth is a byte, so there is no XDR to be done.
There is no justification for the extra cost; it is simply
an expensive implementation.  DCE RPC is worse.
.TSTART
.so ../Results/tmp/lat_udp.tbl
.TEND "UDP latency (microseconds)"
.BU "UDP and RPC/UDP latency" .
UDP sockets are an alternative to TCP sockets.  They differ in that UDP
sockets are unreliable messages that leave the retransmission issues to
the application.  UDP sockets have a few advantages, however.  They preserve
message boundaries, whereas TCP does not; and a single UDP socket may 
send messages
to any number of other sockets, whereas TCP sends data to only one place.
.PP
UDP and RPC/UDP messages are commonly used in many client/server applications.
NFS is probably the most widely used RPC/UDP application in the world.
.PP
Like TCP latency, UDP latency is measured by having a server process 
that waits for connections
and a client process that connects to the server.  The two processes then
exchange a word between them in a loop.  The latency reported is round-trip
time.  The measurements in Table \n[TABLE] are local or loopback measurements,
since our intent is to show the overhead of the software.
Again, note that the RPC library can add hundreds of microseconds of extra
latency.  
.\" .PP
.\" It is interesting to compare UDP latency with TCP latency.  In many cases the
.\" TCP latency is \fBless\fP than the UDP latency.  This flies in the face
.\" of conventional wisdom, which says that TCP is an inherently more expensive
.\" protocol than UDP.  The reasons that TCP may appear faster are: in this
.\" benchmark, the protocol costs are dwarfed by the other costs (context
.\" switching, system calls, and driver overhead); and TCP is frequently
.\" hand-tuned for performance, while UDP is rarely hand-tuned.
.TSTART
.so ipc.tbl
.TEND "Remote latencies (microseconds)"
.BU "Network latency" .
We have a few results for over the wire latency included in Table \n[TABLE].
As might be expected, the most heavily used network interfaces (i.e., ethernet)
have the lowest latencies.  The times shown include the time on the wire,
which is about 130 microseconds for 10Mbit ethernet, 13 microseconds for 100Mbit
ethernet and FDDI, and less than 10 microseconds for Hippi.
.BU "TCP connection latency" .
TCP is a connection-based, reliable, byte-stream-oriented protocol.  As
part of this reliability, a connection must be established before any
data can be transferred.  The connection is accomplished by a ``three-way
handshake,'' an exchange of packets when the client attempts to connect
to the server.
.PP
Unlike UDP, where no connection is established, TCP sends packets
at startup time.  If an application creates a TCP connection to send
one message, then the startup time can be a substantial
fraction of the total connection and transfer costs.   
The benchmark shows that the connection cost is approximately half of
the cost.  
.PP
Connection cost is measured by having a server, registered using
the port mapper, waiting for connections.  The client figures out where the
server is registered and then repeatedly times a \*[connect] system call to
the server.  The socket is closed after each connect.  Twenty connects
are completed and the fastest of them is used as the result.  The time measured
will include two of the three packets that make up the three way TCP handshake,
so the cost is actually greater than the times listed.
.\" XXX Larry --- if a machine's clock granularity is on the order of
.\" 10 milliseconds, won't this benchmark run into granularity problems?
.TSTART
.so ../Results/tmp/lat_connect.tbl
.TEND "TCP connect latency (microseconds)"
.PP
Table \n[TABLE] shows that if the need is to send
a quick message to another process, given that most packets get through,
a UDP message will cost a \f(CWsend\fP and a \f(CWreply\fP (if positive
acknowledgments are needed, which they are in order to have an apples-to-apples 
comparison with TCP).  If the transmission medium is 10Mbit Ethernet, the
time on the wire will be approximately 65 microseconds each way, or 130
microseconds total.  To do the same thing with a short-lived TCP 
connection would cost 896 microseconds of wire time alone.
.PP
The comparison is not meant to disparage TCP; TCP is a useful protocol.  Nor
is the point to suggest that all messages should be UDP.  In many cases,
the difference between 130 microseconds and 900 microseconds is
insignificant compared with other aspects of application performance.
However, if the application is very latency sensitive
and the transmission medium is slow (such as serial link or a message
through many routers), then a UDP message may prove cheaper.
.NH 2 
File system latency
.PP
File system latency is defined as the time required to create or delete
a zero length file.  
We define it this way because in many file systems,
such as the BSD fast file system, the directory operations are done
synchronously in order to maintain on-disk integrity.  Since the 
file data is typically cached and sent to disk at some later date,
the file creation and deletion become the bottleneck
seen by an application.  This bottleneck is substantial: to do
a synchronous update to a disk is a matter of tens of milliseconds.
In many cases, this bottleneck is much more of a perceived performance
issue than processor speed.
.PP
The benchmark creates 1,000 zero-sized files and then deletes them.
All the files are created in one directory and their names are
short, such as "a", "b", "c", ... "aa", "ab", ....
.TSTART
.so lat_fs.tbl
.TEND "File system latency (microseconds)"
.PP
The create and delete latencies are shown in Table \n[TABLE].
Notice that Linux does extremely well here, 2 to 3 orders of magnitude faster
than the slowest systems.  However, Linux does not guarantee
anything about the disk integrity; the directory operations are done in
memory.  Other fast systems, such as SGI's XFS, use a log to guarantee the 
file system integrity.
The slower systems, all those with ~10 millisecond file latencies, are
using synchronous writes to guarantee the file system integrity.
Unless Unixware has modified UFS substantially, they must be running in
an unsafe mode since the FreeBSD UFS is much slower and both file
systems are basically the 4BSD fast file system.
.NH 2
Disk latency
.\" XXX - either get more results for this benchmark or delete it.
.\" I'd really like to not delete it - lmdd is probably the most
.\" useful tool and it gets the least press.
.PP
Included with \*[lmbench] is a small benchmarking program useful for
measuring disk and file I/O.  \*[lmdd], which is patterned after 
the Unix utility \f(CWdd\fP, measures both sequential and random I/O,
optionally generates patterns on output and checks them on input, 
supports flushing the data from the buffer cache on systems that 
support \f(CWmsync\fP, and has a very flexible user interface.  
Many I/O benchmarks can be trivially replaced with a \f(CWperl\fP script
wrapped around \*[lmdd].  
.PP
While we could have generated both sequential and random I/O results as
part of this paper, we did not because those benchmarks are heavily
influenced by the performance of the disk drives used in the test.  We
intentionally measure only the system overhead of a SCSI command since
that overhead may become a bottleneck in large database configurations.
.PP
Some important applications, such as transaction processing, are
limited by random disk IO latency.  
Administrators can increase the number of disk operations per
second by buying more disks, until the processor overhead becomes
the bottleneck.
The \f(CWlmdd\fP  benchmark measures the processor overhead associated with each
disk operation, and it can provide an upper bound on the number of
disk operations the processor can support.
It is designed for SCSI disks, and it assumes that most
disks have 32-128K read-ahead buffers and that they can read ahead
faster than the processor can request the chunks of data.\**
.FS
This may not always be true: a processor could be fast enough to make the
requests faster than the rotating disk.  
If we take 6M/second to be disk
speed, and divide that by 512 (the minimum transfer size), that is 12,288 IOs/second, or
81 microseconds/IO.  We don't know of any processor/OS/IO controller
combinations that can do an IO in 81 microseconds.
.FE
.PP
The benchmark simulates a large number of disks by reading 512byte
transfers sequentially from the raw disk device (raw disks are unbuffered
and are not read ahead by Unix).  
Since the disk can read ahead faster than the system can request
data, the benchmark is doing small transfers of data from the
disk's track buffer.  
Another way to look at this is that the benchmark 
is doing memory-to-memory transfers across a SCSI channel.
It is possible to generate loads of more than 1,000 SCSI
operations/second on a single SCSI disk.  For comparison, disks under
database load typically run at 20-80 operations per second.
.TSTART
.so ../Results/tmp/lat_disk.tbl
.TEND "SCSI I/O overhead (microseconds)"
.PP
The resulting overhead number represents a 
\fBlower\fP bound on the overhead of a disk I/O.  
The real overhead numbers will be higher on SCSI systems because
most SCSI controllers will not disconnect if the request can be
satisfied immediately.
During the benchmark, the processor simply sends the request and
transfers the data, while 
during normal operation, the processor will send the request,
disconnect, get interrupted, reconnect, and transfer the data.
.PP
This technique can be used to discover how many drives a system can support
before the system becomes CPU-limited because it can produce the
overhead load of a fully configured system with just a few disks.
.NH 1
Future work
.PP
There are several known improvements and extensions that could be made
to \*[lmbench].
.BU "Memory latency" .
The current benchmark measures clean-read latency.  By clean, we mean that 
the cache lines being replaced are highly likely to be unmodified, so there
is no associated write-back cost.  We would like to extend the benchmark
to measure dirty-read latency, as well as write latency.  Other changes 
include making the benchmark impervious to sequential prefetching and
measuring TLB miss cost.
.BU "MP benchmarks" .
None of the benchmarks in \*[lmbench] is designed to measure any
multiprocessor features directly.  At a minimum, we could measure 
cache-to-cache latency as well as cache-to-cache bandwidth.
.BU "Static vs. dynamic processes" .
In the process creation section, we allude to the cost of starting up processes
that use shared libraries.  When we figure out how to create statically linked
processes on all or most systems, we could quantify these costs exactly.
.BU "McCalpin's stream benchmark" .
We will probably incorporate part or all of this benchmark into \*[lmbench].
.BU "Automatic sizing" .
We have enough technology that we could determine the size of the external
cache and autosize the memory used such that the external cache had no effect.
.BU "More detailed papers" .
There are several areas that could yield some interesting papers.  The
memory latency section could use an in-depth  treatment, and the
context switching section could turn into an interesting discussion of
caching technology.
.NH 1
Conclusion
.PP
\*[lmbench] is a useful, portable micro-benchmark suite designed to
measure important aspects of system performance.   We have found that a good
memory subsystem is at least as important as the processor speed.
As processors get faster and faster, more and more of the system design
effort will need to move to the cache and memory subsystems.
.NH 1
Acknowledgments
.PP
Many people have provided invaluable help and insight into both the
benchmarks themselves and the paper.  The \s-1USENIX\s0 reviewers
were especially helpful.
We thank all of them
and especially thank:
Ken Okin \s-1(SUN)\s0,
Kevin Normoyle \s-1(SUN)\s0,
Satya Nishtala \s-1(SUN)\s0,
Greg Chesson \s-1(SGI)\s0,
John Mashey \s-1(SGI)\s0,
Neal Nuckolls \s-1(SGI)\s0,
John McCalpin \s-1(Univ. of Delaware)\s0,
Ron Minnich \s-1(Sarnoff)\s0,
Chris Ruemmler \s-1(HP)\s0,
Tom Rokicki \s-1(HP)\s0,
and 
John Weitz \s-1(Digidesign)\s0.
.PP
We would also like to thank all of the people that have run the
benchmark and contributed their results; none of this would have been possible
without their assistance.
.PP
Our thanks to 
all of the free software community for tools that were used during this
project.
\*[lmbench] is currently developed on Linux, a copylefted Unix written by 
Linus Torvalds and his band of happy hackers.
This paper and all of the 
\*[lmbench] documentation was produced using
the \f(CWgroff\fP suite of tools written by James Clark.
Finally, all of the data processing of the results is done with
\f(CWperl\fP written by Larry Wall.  
.PP
Sun Microsystems, and in particular Paul Borrill,
supported the initial development of this project.  Silicon Graphics
has supported ongoing development that turned into far more time then we 
ever imagined.  We are grateful to both of these companies for their
financial support.
.NH 1
Obtaining the benchmarks
.PP
The benchmarks are available at
.ft I
http://reality.sgi.com/employees/lm_engr/lmbench.tgz
.ft
as well as via a mail server.
You may request the latest version of \*[lmbench] by sending email 
to \fIarchives@slovax.engr.sgi.com\fP with \fIlmbench-current*\fP 
as the subject.
.\" .R1
.\" bibliography references
.\" .R2
.\"********************************************************************
.\" Redefine the IP paragraph format so it won't insert a useless line
.\" break when the paragraph tag is longer than the indent distance
.\"
.de @IP
.if \\n[.$]>1 .nr \\n[.ev]:ai (n;\\$2)
.par*start \\n[\\n[.ev]:ai] 0
.if !'\\$1'' \{\
.	\" Divert the label so as to freeze any spaces.
.	di par*label
.	in 0
.	nf
\&\\$1
.	di
.	in
.	fi
.	chop par*label
.	ti -\\n[\\n[.ev]:ai]u
.	ie \\n[dl]+1n<=\\n[\\n[.ev]:ai] \\*[par*label]\h'|\\n[\\n[.ev]:ai]u'\c
.	el \{\
\\*[par*label]
.\".	br
.	\}
.	rm par*label
.\}
..
.\"********************************************************************
.\" redefine the way the reference tag is printed so it is enclosed in
.\" square brackets
.\"
.de ref*end-print
.ie d [F .IP "[\\*([F]" 2
.el .XP
\\*[ref*string]
..
.\"********************************************************************
.\" Get journal number entries right.  Now will print as V(N) rather
.\" than the awful V, N.
.\"
.de ref*add-N
.ref*field N "" ( ) 
..
.\"********************************************************************
.\" Get journal volume entries right.  Now will print as V(N) rather
.\" than the awful V, N.
.\"
.de ref*add-V
.ref*field V , "" "" ""
..
.\"********************************************************************
.\" Get the date entry right.  Should not be enclosed in parentheses.
.\"
.de ref*add-D
.ref*field D ","
..
.R1
accumulate
sort A+DT
database references
label-in-text
label A.nD.y-2
bracket-label [ ] ", "
bibliography references
.R2
.so bios
