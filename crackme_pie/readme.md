# crackme1 - DEF CON CTF Qualifier 2017

This is a crackme taken from the defcon ctf qualifier 2017.

I haven't participated to this ctf, I got the binary from a friend and tried to exploit it with angr.

# Information

security

![checksec](https://image.ibb.co/jXZmQk/checksec.png)

main

![main](https://image.ibb.co/igXFkk/main.png)

shared objects dependencies

```bash
linux-vdso.so.1 =>  (0x00007ffcbc7f3000)
libc.musl-x86_64.so.1 => not found
```

It prints 'enter code:', reads some string from stdin, calls function 0x6c6 and prints 'sum is %ld'.

Trying to enter a string 'test', 'sum is %ld' isn't printed out so exit is called in the function 0x6c6.

libc used is musl. Angr can't load the SimProcedures (I tried with no success, maybe I'm not up to date) from that libc so I call hook_symbol on the necessaries function with the libc.6.so.

![function](https://image.ibb.co/ii9T5k/function.png)

# Link

- [musl](https://www.musl-libc.org/)
