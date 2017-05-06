# simple crackme

```usage: ./crackme password```

# Info

It's a simple crackme that takes a string in argv1 and check if the string is equal to the one in the binary.

# compile

- crackme32

```gcc -m32 -o crackme32 crackme.c```

- crackme64

```gcc -o crackme64 crackme.c```

- crackmestr

```gcc -m32 -o crackmestr crackme.c -static```

```strip -s crackmestr```
