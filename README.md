# strace-ui

`strace-ui` is an strace UI. It looks like this:

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────┐
│╭ Syscalls ─────────────────── f:all ╮╭ Details <tab> ─────────────────────────────── x:auto m:man ╮│
││  execve("/usr/bin/ping",...)      0││ recvmsg  pid 7 (#0)  15:04:20.358200064  0.000150s         ││
││  brk(NULL)                   0x558>││ ping localhost                                             ││
││  access("/etc/ld.so.prel...) ENOENT││ Receive a message from a socket                            ││
││  openat(AT_FDCWD, "/lib6...)      3││ ssize_t recvmsg(int sockfd , struct msghdr * msg , int flag││
││  read(3, "\x7fELF\x02\x0...)    832││                                                            ││
││  fstat(3, {st_mode=S_IFR...)      0││ Arguments                                                  ││
││  mmap(NULL, 4020448, PRO...) 0x7f6>││ sockfd: 3<PING:[140199664]>                                ││
││  close(3)                         0││     ↳ fd 3 from: socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP) ││
││  socket(AF_INET, SOCK_DG...)      3││ msg:                                                       ││
││  connect(3, {sa_family=A...)      0││ ├─msg_name                                                 ││
││  sendto(3, "\x08\x00\xe1...)     64││ │ ├─sa_family = AF_INET                                    ││
││  recvmsg(3, {msg_name={s...)     64││ │ ├─sin_port = htons(0)                                    ││
││  write(1, "64 bytes from...)     64││ │ ╰─sin_addr = inet_addr("127.0.0.1")                      ││
│╰───────────────────────────── 12/13 ╯│ ├─msg_namelen = 128 => 16                                  ││
│                                      │ ├─msg_iov                                                  ││
│                                      │ │ ╰─[0]                                                    ││
│                                      │ │   ├─iov_base =                                           ││
│                                      │ │   │ 0000 00 00 e9 2f 00 6c 00 01 │00./0l01│              ││
│                                      │ │   │ 0008 ba 07 8e 69             │.7.i    │              ││
│                                      │ │   ╰─iov_len = 192                                        ││
│                                      ╰────────────────────────────────────────────────────────────╯│
└────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

![GIF demo of strace-ui](./demos/demo.gif)

## Installation

1. If you are new to OCaml - or if you haven't already - **install
   [opam](https://opam.ocaml.org/)**. It is OCaml's package manager
   and we'll be using it to install `strace-ui` and its dependencies.
   The specific installation instructions depend on your platform. You
   can find platform-specific instructions
   [here](https://opam.ocaml.org/doc/Install.html).
2. `strace-ui` uses [OxCaml](https://oxcaml.org/) so the next thing
   you'll want to do is install `oxcaml` by following the instructions
   [here](https://oxcaml.org/get-oxcaml/).
3. Run `opam install strace-ui`. This will install the `strace-ui`
   binary onto your `PATH`, along with its dependencies.

Note that `strace-ui` shells out to `strace`, so you'll also need to have
`strace` available on your `PATH`.

## Usage

You can invoke it roughly like you would invoke strace:

```
strace-ui ping localhost
strace-ui -p 12345 -e !futex
```

Which will invoke strace for you with roughly these arguments:

```
strace \
  --absolute-timestamps=format:unix,precision:us \
  --syscall-times \
  --follow-forks \
  --decode-fds=all \
  --no-abbrev \
  --strings-in-hex=non-ascii \
  --string-limit=1024 \
  -- ping localhost
```

It has some features that make the output easier to understand, like associating
`<unfinished ...>` calls with their eventual completion in multi-process output, parsing
and rendering structs nicely, and rendering buffers as hexdumps instead of escaped
strings.

It also tracks file descriptor provenance, and lets you filter to all syscalls that create
or reference a given FD. It tries to track FD provenance even across forks, but if you're
attaching to an already-running process that will not work very well. Still, you can
easily see e.g. all `write()` calls a process makes to a given FD by pressing `F`.

`strace-ui` uses `--decode-fds=all` to show more information about FDs, even if it you weren't
tracing at the time that the FD was created. But it augments the output by resolving IP
addresses to domain names when possible. That means instead of seeing:

```
read(18<TCP:[30.32.177.12:44878->30.32.107.76:44563]>, ...)
```

You'll see something like:

```
read(18<TCP:[foo:44878->bar:44563]>, ...)
```

`-e` controls the underlying strace call that we make, but you can filter syscalls
after-the-fact: even if you capture everything, you can dynamically filter what you see in
the syscall list by pressing `f` (or `%` or `h`)

Press `F1` or `?` for a list of keyboard shortcuts:

```ocaml
┌────────────────────────────────────────────────────────────────────────────────────────────────────┐
│╭ Syscalls ──────────────╭────────────────────────────────────────────────╮────────── x:auto m:man ╮│
││  execve("/usr/bin/ping"│ Keyboard Shortcuts                             │0064  0.000150s         ││
││  brk(NULL)             │                                                │                        ││
││  access("/etc/ld.so.pre│ F1 / ?  Toggle this help                       │                        ││
││  openat(AT_FDCWD, "/lib│ Tab     Switch focus between list and details  │ msghdr * msg , int flag││
││  read(3, "\x7fELF\x02\x│ f       Edit filter expression                 │                        ││
││  fstat(3, {st_mode=S_IF│ /       Grep (start regex filter)              │                        ││
││  mmap(NULL, 4020448, PR│ %       Cycle family presets                   │                        ││
││  close(3)              │ h       Hide selected syscall                  │CK_DGRAM, IPPROTO_ICMP) ││
││  socket(AF_INET, SOCK_D│ H       Show only selected syscall             │                        ││
││  connect(3, {sa_family=│ p       Filter to selected PID                 │                        ││
││  sendto(3, "\x08\x00\xe│ P       Exclude selected PID                   │                        ││
││  recvmsg(3, {msg_name={│ x       Cycle display mode (auto/hex/str)      │                        ││
││  write(1, "64 bytes fro│ m       Toggle man page                        │")                      ││
│╰────────────────────────│ d / u   Page down / up                         │                        ││
│                         │ g / G   Jump to top / bottom                   │                        ││
│                         │ F       Follow selected FD                     │                        ││
│                         │ < / >   Jump to prev / next syscall on same FD │                        ││
│                         │ ^       Jump to FD origin (open/socket/etc.)   ││00./0l01│              ││
│                         │ Alt-f   Clear filter                           ││.7.i    │              ││
│                         │ Ctrl-c  Quit                                   │                        ││
│                         │                                                │────────────────────────╯│
└────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

## CLI

```
* main.exe

: strace-ui - interactive strace viewer
:
:   main.exe [[PROGRAM ...]]
:
: === flags ===
:
:   [-- PROGRAM]               . run PROGRAM
:   [-e EXPR]                  . Trace expression passed to strace (e.g.
:                                trace=%net)
:   [-p PID]                   . Attach to an existing process
:   [-theme THEME]             . Color theme (Mocha, Macchiato, Frappe, Latte)
:   [-build-info]              . print info about this build and exit
:   [-version]                 . print the version of this build and exit
:   [-help], -?                . print this help text and exit
```
