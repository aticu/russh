# Russh - RUst SSH

Russh is a Rust only, asynchronous implementation of the SSH protocol.

---

## Current status

Russh is currently work in progress.
A lot of things are not quite done yet and the API is not stable either.
Also a lot of code still needs to be refactored.
**It is currently not recommended to use russh in production.**

The goals listed in the following sections act as guidelines for the design process and are currently not all being fulfilled.

---

## Goals

Russh has the following goals, in order of priority.

### Correctness

Russh should be a correct implementation of the SSH protocol.

### Rust only

Russh should be free from non-Rust dependencies, with the only exception being `libc`.
However it is still possible to use tried and tested non-Rust implementations of cryptographic algorithms, if you prefer that.

### Security

Russh should follow the best security practices.
This includes things like zeroing keys, after they've been used.

### Customizability

Almost every aspect of a connection made by russh should be customizable out of the box.
This includes things like the cryptographic algorithms used by the connection and even how much random padding to add at the end of a packet.

### Ease of use

Russh should be easy to use and to extend.
Getting a full connection with sensible defaults up and running should not take more than a couple lines of code.
The whole API should be well documented.

Also it should be possible to just use what you need.
If your application just requires the basic SSH transport layer to be set up, but no authentication, you can use the `russh-transport` crate directly.

### Readability and maintainability

Russh should be easy to understand and to modify.
Every aspect of the source code should be understandable without having to invest much time into understanding the context around it.

### Performance

Russh should be as fast as possible, while still following all it's other goals.

---

## Contributing

If you want to contribute to russh, feel free to open a issue.

If you'd rather help by writing code, here are some thing you could do:

- Document existing code
- Add tests for existing code
- Fix sections of code that are marked with a `TODO`.
  All of these should be gone, before russh is released.
- Refactor some of the less readable parts of russh.
- Implement more algorithms in the `russh-algorithms` crate.
- Start work on a `russh-auth` crate, that implements user authentication on top of the `russh-transport` crate.

If you know the SSH protocol well enough or know a lot about cryptography implementations, your audit of the Project would be more than welcome.
