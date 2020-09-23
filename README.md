# rust-sha1
A Rust SHA1 implementation created for use in my personal software projects. I wanted a more reasonable (in my opinion) API and I thought it would be an interesting project.

The library is fully documented. Documentation can be generated with `cargo doc`.

Tests can be run with the `cargo test` command, and benchmarks can be run with the `cargo bench` command.

On my computers, my implementation is about 35% slower than other available Rust SHA1 libraries that I tested. The "Hello World!" hash takes about 200ns for my implementation, and about 150ns for the two implementations taken from libraries.
