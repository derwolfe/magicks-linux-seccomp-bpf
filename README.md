## Working on trying to learn how to use seccomp+bpf (seccomp-2)

### Goal: learn enough about seccomp-bpf to be able to help write a sandbox for some ImageMagick code.

### Things I've tried. Things that are being worked on.

1. Started out by reading https://blog.yadutaf.fr/2014/05/29/introduction-to-seccomp-bpf-linux-syscall-filter/.
2. Went to Kees Cook's article on using seccomp-bpf https://outflux.net/teach-seccomp/. Tooled around with the example code.
3. Attempted to write a sandbox policy using libssecomp, got confused by not being able to inspect the syscalls that were failing. I'm sure I was setting up auditing/logging/etc wrong, but this was challenging. I straced the non-sandboxed program and then tried to add policies for each unique syscall. This _still_ failed.
4. Read over http://man7.org/conf/lpc2015/limiting_kernel_attack_surface_with_seccomp-LPC_2015-Kerrisk.pdf
5. Went back to Kees' code and realized that I hadn't understood it. This time around I went through and made a similar policy to what I tried in (3). This works. Next I would like to work on restricting file writes.
6. Starting to work on porting things to libseccomp.
7. Found Paul Moore's presentation on state of seccomp-2 and libseccomp, http://www.paul-moore.com/docs/devconf-syscall_filtering-pmoore-012014-r1.pdf

### I want to run this. How do I?

I've setup a Dockerfile to use an unstable debian release and install most of the things I needed to use when in the container and running it. The most helpful commands are `./doc-rebuild.sh` and `./dock-run.sh`. These do what they sound like. Since the files are shared, I just edit using my normal editor from the host.
