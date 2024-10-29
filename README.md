# plugshark - An experimental Wireshark dissector framework for Rust

Plugshark provides a framework for writing Wireshark dissector plugins. Projects utilizing
this framework can build dynamic libraries that can be loaded into Wireshark to build
protocol analyzers.

Plugshark is (currently) an unsafe plugin framework and provides no memory safety guarentees. While the
project is written to be memory safe, the Wireshark plugin interface does not always establish clear
rules on memory management. Therefore, the interfaces are marked unsafe until proper testing is performed.

All users of the framework must understand that this is still experimental and is not the basis for any
commercial or security-critical application.

Currently supports: **Wireshark v4.4 for Linux**

## How to Use

Follow the <a href="simple-example">simple-example</a> template in this repo to begin a new project.

Add to your `Cargo.toml` using:
- `plugshark = { git = "https://github.com/Gbps/plugshark", tag = "0.0.1" }`

Compiled `libfoo.so` files can be loaded into Wireshark by putting it into your local plugins directory:

```
cp ./target/debug/libfoo.so ~/.local/lib/wireshark/plugins/4.4/epan/
```

## Example

For a more complex example, see: https://github.com/Gbps/elpis-parser

```rust
// Callback for dissection, called when a packet for this protocol is detected and dissected.
unsafe fn dissect_callback(mut tree: DissectorSubTree) {
    // Setting the info column
    tree.set_info_column("This is some info"); 

    // Pushing a single field into the dissector
    tree.add_field("test.u32", IndexPosition::Current(0), 4, FieldEncoding::LittleEndian);

    // Using the same field id multiple times
    tree.add_field("test.u8", IndexPosition::Current(0), 1, FieldEncoding::LittleEndian);
    tree.add_field("test.u8", IndexPosition::Current(0), 1, FieldEncoding::LittleEndian);
    tree.add_field("test.u8", IndexPosition::Current(0), 1, FieldEncoding::LittleEndian);

    // Appending text to the field
    let mut test = tree.add_field("test.u8", IndexPosition::Current(0), 1, FieldEncoding::LittleEndian);
    test.append_text(" (Some Appended Text)");
}
```

Result from [tshark](https://www.wireshark.org/docs/man-pages/tshark.html):

```
User Datagram Protocol, Src Port: 56265, Dst Port: 1234
    Source Port: 56265
    Destination Port: 1234
    Length: 17
    Checksum: 0xfe24 [unverified]
    [Checksum Status: Unverified]
    [Stream index: 0]
    [Stream Packet Number: 1]
    [Timestamps]
        [Time since first frame: 0.000000000 seconds]
        [Time since previous frame: 0.000000000 seconds]
    UDP payload (9 bytes)
Test Protocol
    UInt32 Field: 0x64636261
    UInt8 Field: Test1 (0x65)
    UInt8 Field: Test2 (0x66)
    UInt8 Field: Test3 (0x67)
    UInt8 Field: Test4 (0x68) (Some Appended Text)
```

## Motivation

Currently there are only two official options for writing Wireshark dissectors, either using
the [poorly documented C API](https://www.wireshark.org/docs/wsdg_html_chunked/ChDissectAdd.html) or
the less performant [Lua API](https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm_modules.html).

There exists a Rust project for creating dissectors called [WSDF](https://github.com/ghpr-asia/wsdf), but
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
