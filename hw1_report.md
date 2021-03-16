# Linux v5.11 m400 HypSec Adaptation Report

## Status

As of now, I have the provided guest kernel running under HypSec on Linux v5.11,
on m400 hardware. However, this only works for a single-core VM—for reasons yet
to be determined, running with SMP results in the host attempting to access pages
owned by the VM (specifically, those mapped by the KVM\_ARM\_SET\_BOOT\_INFO ioctl),
thereby faulting to oblivion. My current speculation is that this is caused by
some complication with COW pages—I notice that the first boot info page loaded
by QEMU faults on write for a broken SMP run (attempting to unmap stage2 pages
in the process) where this doesn't happen on v4.18 or a single-core v5.11 run
(which makes sense, as QEMU probably isn't forking in this case, so no need for
COW). I'll also note that the GUP interface and internals have changed
considerably since v4.18/v5.4, and there is definitely chatter with regard to
potential issues with getting COW pages.

## Benchmarks

Below are the local benchmarks comparing stock KVM's single-core performance to
that of HypSec (both on v5.11, built from this repo). Unfortunately, I am unable
to test with networking benchmarks due to v5.11 PCI driver bugs which affect
m400 hardware, causing an immediate kernel crash under any significant network
duress. This is evidenced by merely attempting to `git clone` a repo on stock
v5.11, or running the given Apache stress test. So of course, this issue is
completely unrelated to virtualization.

### Stock KVM (`CONFIG\_VERIFIED\_KVM=n`)

```
$ ./hackbench 100 process 500
Running with 100*40 (== 4000) tasks.
Time: 77.868

$ make allnoconfig
…
$ make -j$(nproc)
…
real	4m4.969s
user	3m44.198s
sys	0m19.218s
```

### HypSec (`CONFIG\_VERIFIED\_KVM=y`)

```
$ ./hackbench 100 process 500
Running with 100*40 (== 4000) tasks.
Time: 77.748

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
directory tree restructuring, which has taken place.

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
same symbols as non-VHE, but without the aforementioned prefix). All-in-all,
this took a long time.

### Booting

TODO

### Running a VM

TODO
