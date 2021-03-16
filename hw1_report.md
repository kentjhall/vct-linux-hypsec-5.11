# Linux v5.11 m400 HypSec Adaptation Report

## Status

As of now, I have the provided guest kernel running under HypSec on Linux v5.11,
on m400 hardware. However, this only works for a single-core VM—for reasons yet
to be determined, running with SMP results in the host attempting to access pages
owned by the VM (specifically, those mapped by the `KVM_ARM_SET_BOOT_INFO` ioctl),
thereby faulting to oblivion. My current speculation is that this is caused by
some complication with COW pages—I notice that the first boot info page loaded
by QEMU faults on write for a broken SMP run (attempting to unmap stage2 pages
in the process) where this doesn't happen on v4.18 or a single-core v5.11 run
(which makes sense, as QEMU probably isn't forking in this case, so no need for
COW). I'll also note that the GUP interface and internals have changed
considerably since v4.18/v5.4, and there is definitely chatter with regard to
potential issues with getting COW pages.

## Running

To run, I simply use the provided `run_guest.sh` script as specified, with the
caveat that `-c 1` must be passed (for single-core). Prior to this, I copied
benchmarks onto the disk image by mounting with `qemu-nbd`.

## Benchmarks

Below are the local benchmarks comparing stock KVM's single-core performance to
that of HypSec (both on v5.11, built from this repo). Unfortunately, I am unable
to test with networking benchmarks due to v5.11 PCI driver bugs which affect
m400 hardware, causing an immediate kernel crash under any significant network
duress. This is evidenced by merely attempting to `git clone` a repo on stock
v5.11, or running the given Apache stress test. So of course, this issue is
completely unrelated to virtualization.

### Stock KVM (`CONFIG_VERIFIED_KVM=n`)

#### Hackbench

```
$ ./hackbench 100 process 500
Running with 100*40 (== 4000) tasks.
Time: 77.868
```

#### Linux 4.9 kernel compilation

```
$ make allnoconfig
…
$ make -j$(nproc)
…
real	4m4.969s
user	3m44.198s
sys	0m19.218s
```

### HypSec (`CONFIG_VERIFIED_KVM=y`)

#### Hackbench

```
$ ./hackbench 100 process 500
Running with 100*40 (== 4000) tasks.
Time: 77.748
```

#### Linux 4.9 kernel compilation

```
$ make allnoconfig
…
$ make -j$(nproc)
…
real	4m8.629s
user	3m45.996s
sys	0m20.635s
```

## Challenges

Porting HypSec to Linux v5.11 came with no shortage of challenges, the extent of
which I detail below.

### Merging

I began by merging the existing v4.18 version of HypSec into my stock v5.11 
starting point. This of course came with plenty of merge conflicts to sort out,
which was an unpleasant introduction to the significant interface changes, and
directory tree restructuring, which has taken place. Nevermind KVM's MMU code,
which is completely restructured—no longer is it a simple hop from one function
to the next for a page walk, but instead a convoluted system of recursion and
function pointers to generically traverse each level. Making sense of it, and
applying the necessary HypSec changes, was certainly a challenge.

### Compiling/Linking

Compiling, of course, was just a matter of fixing the things that I had merged
incorrectly. But the first real challenge of the project came at the linking
stage—with regard to non-VHE EL2 code, things have changed considerably since
v4.18 (and v5.4, for that matter). Now, there is no longer the `__hyp_text`
compiler attribute for specifying EL2 code. Instead, all non-VHE EL2 code is
kept in `arch/arm64/kvm/hyp/nvhe/`, purposefully isolated from EL1 code. There
is a special script in the Makefile for this directory which essentially makes
everything `__hyp_text`, but then also prefixes all symbols with `__kvm_nvhe_`,
to establish a segregated namespace. These things being the case, I had to have
HypSec's EL2 code build by this Makefile (rather than the one in
`hypsec_proven/`. Additionally, I ended up moving all the HypSec EL2 source
files into this `arch/arm64/kvm/hyp/nvhe/` directory, to keep in line with the
intent behind segregating EL2 code. Besides this restructuring, there were also
many linker errors which arose from HypSec code using symbols no longer
available in EL2, as well as errors arising from the VHE code (which has all the
same symbols as non-VHE, but without the aforementioned prefix), as certain
source files modified for HypSec are compiled for both VHE and non-VHE.

### Booting

Booting challenges came primarily from originally trying to merge v4.18 HypSec
assembly modifications for EL2 entry/exit into v5.11. This approach proved
infeasible, as the structuring for v5.11 is too much changed. For example, in
v4.18/v5.4, the same HYP vector was used for both host and guest operating
systems, but in v5.11, the host has its own dedicated vector, with corresponding
entry/exit routines. I ultimately found it easier to gain an understanding of
the intent behind the v4.18 modifications, and to apply this manually to the
new v5.11 structure (rather than haphazardly mashing code together). So with the
host vector example, I came to realize that this change was actually to my
benefit—in v4.18, the HypSec code was setting the `tpidr_el2` system register to
`0` on the host, so as to distinguish it from the guest on EL2 entry/exit. (This
was necessary because stock Linux was using `vttbr_el2` for this instead, but
HypSec of course needs this to be set for the host, as it must use Stage 2
paging as well). But since v5.11 has entirely separate code paths for the host
and guest, it is no longer necessary to distinguish by a register, and so I am
free to leave `tpidr_el2` set normally (which is useful, as much heavier use is
made of the per-cpu memory it points to in v5.11). Additionally, there is now a
C handler for hypercalls (and other EL2 traps), with a constrained interface
actually more similar to that of HypSec (identifying from a limited set of
actions by a passed integer value, rather than directly jumping to a function
pointer as in previous versions of Linux), so I could leverage this by just
calling HypSec's handlers from there, both for hypercalls and host Stage 2 page
faults. This limited the amount of assembly modifications I needed to make.

### Running a VM

There were, of course, many new issues when it came to actually getting
something running. It took me an unfortunately long time to discover, for
example, that some v5.11 code was setting `hcr_el2` (overwriting what was set by
HypSec code), which had been causing my VM to trap when it shouldn't have, and
thereby hit an exception, jumping to some offset from the garbage value stored
in `vbar_el1`. This is just one example, but I had several issues with different
sysregs not being saved or restored properly, and countless hours spent learning
how to debug assembly, finally pinpointing the error, only to spend even more time
afterward on an error caused by my own earlier assembly debugging, as I'd been
squashing some register or another. Unfortunately I don't recall every single issue
I ran into at this point, but you can trust me when I say there were many.
