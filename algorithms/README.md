# Russh algorithms

This crate implements the most common algorithms used by the ssh transport layer.

All of the implemented algorithms are optional and can be enabled separately by cargo features.
For example to just use the `aes128-ctr` algorithm:

```
russh-algorithms = { version = "...", default-features = false, features = ["aes128-ctr"] }
```

This crate is strictly optional for the use of russh and can be disabled in the other crates.
