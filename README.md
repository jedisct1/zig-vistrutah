# Vistrutah

This repository is a Zig implementation of the Vistrutah large-block cipher family. The code is small, direct, and meant to be easy to inspect: one library module in `src/root.zig`, one demo program in `src/main.zig`, and a set of tests that check round trips, mixing layers, and reference vectors.

Vistrutah comes in two block sizes. The 256-bit family works on 32-byte blocks and supports 128-bit or 256-bit keys. The 512-bit family works on 64-byte blocks and supports 256-bit or 512-bit keys. This implementation exposes each variant as its own Zig type, so the choice of block size, key size, and round count is explicit in the API instead of being hidden behind runtime flags.

Under the hood, the cipher uses AES round functions as building blocks, and Zig will use hardware AES support when the target machine provides it. That makes this project a nice fit if you want a readable Zig implementation, a reference for experiments, or a starting point for integrating Vistrutah into a larger codebase.

## Using the library

The package exposes the module as `vistrutah`. Each concrete cipher type provides `block_length`, `key_length`, `encrypt(out, in, key)`, and `decrypt(out, in, key)`.

```zig
const std = @import("std");
const vistrutah = @import("vistrutah");

test "encrypt and decrypt one Vistrutah-256 block" {
    const key = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };

    const plaintext = [_]u8{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    };

    var ciphertext: [vistrutah.Vistrutah256_256.block_length]u8 = undefined;
    var decrypted: [vistrutah.Vistrutah256_256.block_length]u8 = undefined;

    vistrutah.Vistrutah256_256.encrypt(&ciphertext, &plaintext, &key);
    vistrutah.Vistrutah256_256.decrypt(&decrypted, &ciphertext, &key);

    try std.testing.expectEqualSlices(u8, &plaintext, &decrypted);
}
```

If you want different trade-offs, the module exports these variants:

- `Vistrutah256_128_Short`
- `Vistrutah256_256_Short`
- `Vistrutah256_128`
- `Vistrutah256_256`
- `Vistrutah512_256_Short`
- `Vistrutah512_512_Short`
- `Vistrutah512_256`
- `Vistrutah512_512`

The `Short` types use fewer rounds. The non-`Short` types are the longer-round variants.
