const std = @import("std");
const vistrutah = @import("vistrutah");

fn printHex(label: []const u8, data: []const u8) void {
    std.debug.print("{s}: {x}\n", .{ label, data });
}

pub fn main() !void {
    std.debug.print("=== Vistrutah-256 Demo ===\n", .{});
    {
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

        var ciphertext: [32]u8 = undefined;
        var decrypted: [32]u8 = undefined;

        printHex("Key      ", &key);
        printHex("Plaintext", &plaintext);

        vistrutah.Vistrutah256_256.encrypt(&ciphertext, &plaintext, &key);
        printHex("Ciphertext (14 rounds)", &ciphertext);

        vistrutah.Vistrutah256_256.decrypt(&decrypted, &ciphertext, &key);
        printHex("Decrypted", &decrypted);

        if (std.mem.eql(u8, &plaintext, &decrypted)) {
            std.debug.print("Verification: PASSED\n", .{});
        } else {
            std.debug.print("Verification: FAILED\n", .{});
        }
    }

    std.debug.print("\n=== Vistrutah-512 Demo ===\n", .{});
    {
        const key = [_]u8{
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        };

        var plaintext: [64]u8 = undefined;
        for (0..64) |i| {
            plaintext[i] = @truncate((i * 17) & 0xff);
        }

        var ciphertext: [64]u8 = undefined;
        var decrypted: [64]u8 = undefined;

        printHex("Key      ", &key);
        printHex("Plaintext", &plaintext);

        vistrutah.Vistrutah512_256.encrypt(&ciphertext, &plaintext, &key);
        printHex("Ciphertext (14 rounds)", &ciphertext);

        vistrutah.Vistrutah512_256.decrypt(&decrypted, &ciphertext, &key);
        printHex("Decrypted", &decrypted);

        if (std.mem.eql(u8, &plaintext, &decrypted)) {
            std.debug.print("Verification: PASSED\n", .{});
        } else {
            std.debug.print("Verification: FAILED\n", .{});
        }
    }
}

test "simple test" {
    const key = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    const plaintext: [32]u8 = @splat(0);
    var ciphertext: [32]u8 = undefined;
    var decrypted: [32]u8 = undefined;

    vistrutah.Vistrutah256_256.encrypt(&ciphertext, &plaintext, &key);
    vistrutah.Vistrutah256_256.decrypt(&decrypted, &ciphertext, &key);

    try std.testing.expectEqualSlices(u8, &plaintext, &decrypted);
}
