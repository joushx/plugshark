# plugshark - An experimental Wireshark dissector framework for Rust

Plugshark provides a framework for wirting Wireshark dissector plugins. Projects utilizing
this framework can build dynamic libraries that can be loaded into Wireshark to build
protocol analyzers.

Plugshark is (currently) an unsafe plugin framework and provides no memory safety guarentees. While the
project is written to be memory safe, the Wireshark plugin interface does not always establish clear
rules on memory management. Therefore, the interfaces are marked unsafe until proper testing is performed.

All users of the framework are created with the understanding that this is
still experimental.

## How to Use

Check out the <a href="simple-example">simple-example</a> project in this repo for a basic template to extend.

## Motivation

Currently there are only two official options for writing Wireshark dissectors, either using
the [poorly documented C API](https://www.wireshark.org/docs/wsdg_html_chunked/ChDissectAdd.html) or
the less performant [Lua API](https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm_modules.html).

There exists a Rust project for crating dissectors called [WSDF](https://github.com/ghpr-asia/wsdf), but
it mainly focuses on writing analyzers from Rust structures using a declarative method. This doesn't work
so well when you have more complex dissector requirements, such as protocols that work entirely on a bitstream
level.

While the C API supports a wide range of use cases, the API is clunky to use. It is clear that the plugin API
requires a strong understanding of the internals of Wireshark.

The hope of this project is to provide a wrapper that gives relatively good access to the core functionality of
the dissector C API from Rust. Not all features are supported, and PRs are welcome.

## License

<sup>
Licensed under either of <a href="LICENSE-APACHE">Apache License, Version
2.0</a> or <a href="LICENSE-MIT">MIT license</a> at your option.
</sup>

<br>

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
</sub> 
