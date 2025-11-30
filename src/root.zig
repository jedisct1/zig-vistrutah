//! Vistrutah is a large-block cipher family designed for high-performance
//! authenticated encryption modes. It offers two main variants:
//!
//! - Vistrutah-256: 256-bit block size with 128 or 256-bit keys
//! - Vistrutah-512: 512-bit block size with 256 or 512-bit keys
//!
//! The cipher leverages hardware-accelerated AES instructions to achieve
//! exceptional performance while providing strong cryptographic security.
//!
//! Built on a generalized Even-Mansour construction using AES round functions
//! as the underlying permutation, Vistrutah inherits security properties from
//! both constructions while enabling efficient implementation on modern CPUs.

const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const assert = std.debug.assert;

const aes = crypto.core.aes;
const Block = aes.Block;

/// Vistrutah-256 with 128-bit key (short rounds)
pub const Vistrutah256_128_Short = Vistrutah256Generic(.key_128, .short);
/// Vistrutah-256 with 256-bit key (short rounds)
pub const Vistrutah256_256_Short = Vistrutah256Generic(.key_256, .short);
/// Vistrutah-256 with 128-bit key (long rounds)
pub const Vistrutah256_128 = Vistrutah256Generic(.key_128, .long);
/// Vistrutah-256 with 256-bit key (long rounds)
pub const Vistrutah256_256 = Vistrutah256Generic(.key_256, .long);

/// Vistrutah-512 with 256-bit key (short rounds)
pub const Vistrutah512_256_Short = Vistrutah512Generic(.key_256, .short);
/// Vistrutah-512 with 512-bit key (short rounds)
pub const Vistrutah512_512_Short = Vistrutah512Generic(.key_512, .short);
/// Vistrutah-512 with 256-bit key (long rounds)
pub const Vistrutah512_256 = Vistrutah512Generic(.key_256, .long);
/// Vistrutah-512 with 512-bit key (long rounds)
pub const Vistrutah512_512 = Vistrutah512Generic(.key_512, .long);

const rounds_per_step = 2;

const round_constants = [48][16]u8{
    .{ 0x24, 0x3F, 0x6A, 0x88, 0x85, 0xA3, 0x08, 0xD3, 0x13, 0x19, 0x8A, 0x2E, 0x03, 0x70, 0x73, 0x44 },
    .{ 0xA4, 0x09, 0x38, 0x22, 0x29, 0x9F, 0x31, 0xD0, 0x08, 0x2E, 0xFA, 0x98, 0xEC, 0x4E, 0x6C, 0x89 },
    .{ 0x45, 0x28, 0x21, 0xE6, 0x38, 0xD0, 0x13, 0x77, 0xBE, 0x54, 0x66, 0xCF, 0x34, 0xE9, 0x0C, 0x6C },
    .{ 0xC0, 0xAC, 0x29, 0xB7, 0xC9, 0x7C, 0x50, 0xDD, 0x3F, 0x84, 0xD5, 0xB5, 0xB5, 0x47, 0x09, 0x17 },
    .{ 0x92, 0x16, 0xD5, 0xD9, 0x89, 0x79, 0xFB, 0x1B, 0xD1, 0x31, 0x0B, 0xA6, 0x98, 0xDF, 0xB5, 0xAC },
    .{ 0x2F, 0xFD, 0x72, 0xDB, 0xD0, 0x1A, 0xDF, 0xB7, 0xB8, 0xE1, 0xAF, 0xED, 0x6A, 0x26, 0x7E, 0x96 },
    .{ 0xBA, 0x7C, 0x90, 0x45, 0xF1, 0x2C, 0x7F, 0x99, 0x24, 0xA1, 0x99, 0x47, 0xB3, 0x91, 0x6C, 0xF7 },
    .{ 0x08, 0x01, 0xF2, 0xE2, 0x85, 0x8E, 0xFC, 0x16, 0x63, 0x69, 0x20, 0xD8, 0x71, 0x57, 0x4E, 0x69 },
    .{ 0xA4, 0x58, 0xFE, 0xA3, 0xF4, 0x93, 0x3D, 0x7E, 0x0D, 0x95, 0x74, 0x8F, 0x72, 0x8E, 0xB6, 0x58 },
    .{ 0x71, 0x8B, 0xCD, 0x58, 0x82, 0x15, 0x4A, 0xEE, 0x7B, 0x54, 0xA4, 0x1D, 0xC2, 0x5A, 0x59, 0xB5 },
    .{ 0x9C, 0x30, 0xD5, 0x39, 0x2A, 0xF2, 0x60, 0x13, 0xC5, 0xD1, 0xB0, 0x23, 0x28, 0x60, 0x85, 0xF0 },
    .{ 0xCA, 0x41, 0x79, 0x18, 0xB8, 0xDB, 0x38, 0xEF, 0x8E, 0x79, 0xDC, 0xB0, 0x60, 0x3A, 0x18, 0x0E },
    .{ 0x6C, 0x9E, 0x0E, 0x8B, 0xB0, 0x1E, 0x8A, 0x3E, 0xD7, 0x15, 0x77, 0xC1, 0xBD, 0x31, 0x4B, 0x27 },
    .{ 0x78, 0xAF, 0x2F, 0xDA, 0x55, 0x60, 0x5C, 0x60, 0xE6, 0x55, 0x25, 0xF3, 0xAA, 0x55, 0xAB, 0x94 },
    .{ 0x57, 0x48, 0x98, 0x62, 0x63, 0xE8, 0x14, 0x40, 0x55, 0xCA, 0x39, 0x6A, 0x2A, 0xAB, 0x10, 0xB6 },
    .{ 0xB4, 0xCC, 0x5C, 0x34, 0x11, 0x41, 0xE8, 0xCE, 0xA1, 0x54, 0x86, 0xAF, 0x7C, 0x72, 0xE9, 0x93 },
    .{ 0xB3, 0xEE, 0x14, 0x11, 0x63, 0x6F, 0xBC, 0x2A, 0x2B, 0xA9, 0xC5, 0x5D, 0x74, 0x18, 0x31, 0xF6 },
    .{ 0xCE, 0x5C, 0x3E, 0x16, 0x9B, 0x87, 0x93, 0x1E, 0xAF, 0xD6, 0xBA, 0x33, 0x6C, 0x24, 0xCF, 0x5C },
    .{ 0x7A, 0x32, 0x53, 0x81, 0x28, 0x95, 0x86, 0x77, 0x3B, 0x8F, 0x48, 0x98, 0x6B, 0x4B, 0xB9, 0xAF },
    .{ 0xC4, 0xBF, 0xE8, 0x1B, 0x66, 0x28, 0x21, 0x93, 0x61, 0xD8, 0x09, 0xCC, 0xFB, 0x21, 0xA9, 0x91 },
    .{ 0x48, 0x7C, 0xAC, 0x60, 0x5D, 0xEC, 0x80, 0x32, 0xEF, 0x84, 0x5D, 0x5D, 0xE9, 0x85, 0x75, 0xB1 },
    .{ 0xDC, 0x26, 0x23, 0x02, 0xEB, 0x65, 0x1B, 0x88, 0x23, 0x89, 0x3E, 0x81, 0xD3, 0x96, 0xAC, 0xC5 },
    .{ 0x0F, 0x6D, 0x6F, 0xF3, 0x83, 0xF4, 0x42, 0x39, 0x2E, 0x0B, 0x44, 0x82, 0xA4, 0x84, 0x20, 0x04 },
    .{ 0x69, 0xC8, 0xF0, 0x4A, 0x9E, 0x1F, 0x9B, 0x5E, 0x21, 0xC6, 0x68, 0x42, 0xF6, 0xE9, 0x6C, 0x9A },
    .{ 0x67, 0x0C, 0x9C, 0x61, 0xAB, 0xD3, 0x88, 0xF0, 0x6A, 0x51, 0xA0, 0xD2, 0xD8, 0x54, 0x2F, 0x68 },
    .{ 0x96, 0x0F, 0xA7, 0x28, 0xAB, 0x51, 0x33, 0xA3, 0x6E, 0xEF, 0x0B, 0x6C, 0x13, 0x7A, 0x3B, 0xE4 },
    .{ 0xBA, 0x3B, 0xF0, 0x50, 0x7E, 0xFB, 0x2A, 0x98, 0xA1, 0xF1, 0x65, 0x1D, 0x39, 0xAF, 0x01, 0x76 },
    .{ 0x66, 0xCA, 0x59, 0x3E, 0x82, 0x43, 0x0E, 0x88, 0x8C, 0xEE, 0x86, 0x19, 0x45, 0x6F, 0x9F, 0xB4 },
    .{ 0x7D, 0x84, 0xA5, 0xC3, 0x3B, 0x8B, 0x5E, 0xBE, 0xE0, 0x6F, 0x75, 0xD8, 0x85, 0xC1, 0x20, 0x73 },
    .{ 0x40, 0x1A, 0x44, 0x9F, 0x56, 0xC1, 0x6A, 0xA6, 0x4E, 0xD3, 0xAA, 0x62, 0x36, 0x3F, 0x77, 0x06 },
    .{ 0x1B, 0xFE, 0xDF, 0x72, 0x42, 0x9B, 0x02, 0x3D, 0x37, 0xD0, 0xD7, 0x24, 0xD0, 0x0A, 0x12, 0x48 },
    .{ 0xDB, 0x0F, 0xEA, 0xD3, 0x49, 0xF1, 0xC0, 0x9B, 0x07, 0x53, 0x72, 0xC9, 0x80, 0x99, 0x1B, 0x7B },
    .{ 0x25, 0xD4, 0x79, 0xD8, 0xF6, 0xE8, 0xDE, 0xF7, 0xE3, 0xFE, 0x50, 0x1A, 0xB6, 0x79, 0x4C, 0x3B },
    .{ 0x97, 0x6C, 0xE0, 0xBD, 0x04, 0xC0, 0x06, 0xBA, 0xC1, 0xA9, 0x4F, 0xB6, 0x40, 0x9F, 0x60, 0xC4 },
    .{ 0x5E, 0x5C, 0x9E, 0xC2, 0x19, 0x6A, 0x24, 0x63, 0x68, 0xFB, 0x6F, 0xAF, 0x3E, 0x6C, 0x53, 0xB5 },
    .{ 0x13, 0x39, 0xB2, 0xEB, 0x3B, 0x52, 0xEC, 0x6F, 0x6D, 0xFC, 0x51, 0x1F, 0x9B, 0x30, 0x95, 0x2C },
    .{ 0xCC, 0x81, 0x45, 0x44, 0xAF, 0x5E, 0xBD, 0x09, 0xBE, 0xE3, 0xD0, 0x04, 0xDE, 0x33, 0x4A, 0xFD },
    .{ 0x66, 0x0F, 0x28, 0x07, 0x19, 0x2E, 0x4B, 0xB3, 0xC0, 0xCB, 0xA8, 0x57, 0x45, 0xC8, 0x74, 0x0F },
    .{ 0xD2, 0x0B, 0x5F, 0x39, 0xB9, 0xD3, 0xFB, 0xDB, 0x55, 0x79, 0xC0, 0xBD, 0x1A, 0x60, 0x32, 0x0A },
    .{ 0xD6, 0xA1, 0x00, 0xC6, 0x40, 0x2C, 0x72, 0x79, 0x67, 0x9F, 0x25, 0xFE, 0xFB, 0x1F, 0xA3, 0xCC },
    .{ 0x8E, 0xA5, 0xE9, 0xF8, 0xDB, 0x32, 0x22, 0xF8, 0x3C, 0x75, 0x16, 0xDF, 0xFD, 0x61, 0x6B, 0x15 },
    .{ 0x2F, 0x50, 0x1E, 0xC8, 0xAD, 0x05, 0x52, 0xAB, 0x32, 0x3D, 0xB5, 0xFA, 0xFD, 0x23, 0x87, 0x60 },
    .{ 0x53, 0x31, 0x7B, 0x48, 0x3E, 0x00, 0xDF, 0x82, 0x9E, 0x5C, 0x57, 0xBB, 0xCA, 0x6F, 0x8C, 0xA0 },
    .{ 0x1A, 0x87, 0x56, 0x2E, 0xDF, 0x17, 0x69, 0xDB, 0xD5, 0x42, 0xA8, 0xF6, 0x28, 0x7E, 0xFF, 0xC3 },
    .{ 0xAC, 0x67, 0x32, 0xC6, 0x8C, 0x4F, 0x55, 0x73, 0x69, 0x5B, 0x27, 0xB0, 0xBB, 0xCA, 0x58, 0xC8 },
    .{ 0xE1, 0xFF, 0xA3, 0x5D, 0xB8, 0xF0, 0x11, 0xA0, 0x10, 0xFA, 0x3D, 0x98, 0xFD, 0x21, 0x83, 0xB8 },
    .{ 0x4A, 0xFC, 0xB5, 0x6C, 0x2D, 0xD1, 0xD3, 0x5B, 0x9A, 0x53, 0xE4, 0x79, 0xB6, 0xF8, 0x45, 0x65 },
    .{ 0xD2, 0x8E, 0x49, 0xBC, 0x4B, 0xFB, 0x97, 0x90, 0xE1, 0xDD, 0xF2, 0xDA, 0xA4, 0xCB, 0x7E, 0x33 },
};

const p4 = [16]u8{ 9, 7, 13, 14, 0, 10, 3, 5, 1, 2, 15, 4, 6, 12, 11, 8 };
const p5 = [16]u8{ 12, 8, 1, 9, 15, 4, 0, 3, 14, 10, 6, 7, 2, 5, 13, 11 };
const p4_inv = [16]u8{ 4, 8, 9, 6, 11, 7, 12, 1, 15, 0, 5, 14, 13, 2, 3, 10 };
const p5_inv = [16]u8{ 6, 2, 12, 7, 5, 13, 10, 11, 1, 3, 9, 15, 0, 14, 8, 4 };

const kexp_shuffle = [32]u8{
    30, 29, 8,  23, 10, 9,  20, 3,  22, 21, 0,  31, 2,  1,  28, 11,
    14, 13, 24, 7,  26, 25, 4,  19, 6,  5,  16, 15, 18, 17, 12, 27,
};

const vzip = [64]u8{
    0,  16, 32, 48, 1,  17, 33, 49, 2,  18, 34, 50, 3,  19, 35, 51,
    8,  24, 40, 56, 9,  25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59,
    4,  20, 36, 52, 5,  21, 37, 53, 6,  22, 38, 54, 7,  23, 39, 55,
    12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63,
};

const vunzip = [64]u8{
    0, 4, 8,  12, 32, 36, 40, 44, 16, 20, 24, 28, 48, 52, 56, 60,
    1, 5, 9,  13, 33, 37, 41, 45, 17, 21, 25, 29, 49, 53, 57, 61,
    2, 6, 10, 14, 34, 38, 42, 46, 18, 22, 26, 30, 50, 54, 58, 62,
    3, 7, 11, 15, 35, 39, 43, 47, 19, 23, 27, 31, 51, 55, 59, 63,
};

const zero_block = Block.fromBytes(&[_]u8{0} ** 16);

fn applyPermutation16(comptime perm: [16]u8, data: *[16]u8) void {
    const temp = data.*;
    inline for (0..16) |i| {
        data[i] = temp[perm[i]];
    }
}

fn applyPermutation64(comptime perm: [64]u8, data: *[64]u8) void {
    const temp = data.*;
    inline for (0..64) |i| {
        data[i] = temp[perm[i]];
    }
}

fn rotateBytes16(data: *[16]u8, shift: usize) void {
    const temp = data.*;
    for (0..16) |i| {
        data[i] = temp[(i + shift) % 16];
    }
}

fn mixingLayer256(state: *[32]u8) void {
    var temp: [32]u8 = undefined;
    for (0..16) |i| {
        temp[i] = state[2 * i];
        temp[16 + i] = state[2 * i + 1];
    }
    state.* = temp;
}

fn invMixingLayer256(state: *[32]u8) void {
    var temp: [32]u8 = undefined;
    for (0..16) |i| {
        temp[2 * i] = state[i];
        temp[2 * i + 1] = state[16 + i];
    }
    state.* = temp;
}

fn mixingLayer512(state: *[64]u8) void {
    applyPermutation64(vzip, state);
}

fn invMixingLayer512(state: *[64]u8) void {
    applyPermutation64(vunzip, state);
}

const KeySize256 = enum { key_128, key_256 };
const KeySize512 = enum { key_256, key_512 };
const RoundMode = enum { short, long };

fn Vistrutah256Generic(comptime key_size: KeySize256, comptime round_mode: RoundMode) type {
    return struct {
        const Self = @This();

        /// Block length in bytes.
        pub const block_length = 32;
        /// Key length in bytes.
        pub const key_length = switch (key_size) {
            .key_128 => 16,
            .key_256 => 32,
        };

        const num_rounds = switch (round_mode) {
            .short => 10,
            .long => 14,
        };
        const steps = num_rounds / rounds_per_step;

        /// Encrypt a single block.
        pub fn encrypt(out: *[block_length]u8, in: *const [block_length]u8, key: *const [key_length]u8) void {
            var state: [32]u8 = in.*;
            var fixed_key: [32]u8 = undefined;

            if (key_length == 16) {
                @memcpy(fixed_key[0..16], key);
                @memcpy(fixed_key[16..32], key);
            } else {
                fixed_key = key.*;
            }

            var round_key: [32]u8 = undefined;
            @memcpy(round_key[0..16], fixed_key[16..32]);
            @memcpy(round_key[16..32], fixed_key[0..16]);

            for (0..32) |i| {
                state[i] ^= round_key[i];
            }

            var s0 = Block.fromBytes(state[0..16]);
            var s1 = Block.fromBytes(state[16..32]);
            const fk0 = Block.fromBytes(fixed_key[0..16]);
            const fk1 = Block.fromBytes(fixed_key[16..32]);

            s0 = s0.encrypt(fk0);
            s1 = s1.encrypt(fk1);

            for (1..steps) |i| {
                s0 = s0.encrypt(zero_block);
                s1 = s1.encrypt(zero_block);

                state[0..16].* = s0.toBytes();
                state[16..32].* = s1.toBytes();

                mixingLayer256(&state);

                applyPermutation16(p4, round_key[0..16]);
                applyPermutation16(p5, round_key[16..32]);

                for (0..32) |j| {
                    state[j] ^= round_key[j];
                }

                for (0..16) |j| {
                    state[j] ^= round_constants[i - 1][j];
                }

                s0 = Block.fromBytes(state[0..16]);
                s1 = Block.fromBytes(state[16..32]);

                s0 = s0.encrypt(fk0);
                s1 = s1.encrypt(fk1);
            }

            applyPermutation16(p4, round_key[0..16]);
            applyPermutation16(p5, round_key[16..32]);

            const rk0 = Block.fromBytes(round_key[0..16]);
            const rk1 = Block.fromBytes(round_key[16..32]);

            s0 = s0.encryptLast(rk0);
            s1 = s1.encryptLast(rk1);

            out[0..16].* = s0.toBytes();
            out[16..32].* = s1.toBytes();
        }

        /// Decrypt a single block.
        pub fn decrypt(out: *[block_length]u8, in: *const [block_length]u8, key: *const [key_length]u8) void {
            var state: [32]u8 = in.*;
            var fixed_key: [32]u8 = undefined;

            if (key_length == 16) {
                @memcpy(fixed_key[0..16], key);
                @memcpy(fixed_key[16..32], key);
            } else {
                fixed_key = key.*;
            }

            var round_key: [32]u8 = undefined;
            @memcpy(round_key[0..16], fixed_key[16..32]);
            @memcpy(round_key[16..32], fixed_key[0..16]);

            for (0..steps) |_| {
                applyPermutation16(p4, round_key[0..16]);
                applyPermutation16(p5, round_key[16..32]);
            }

            var dec_fixed_key: [32]u8 = undefined;
            const dfk0 = Block.fromBytes(fixed_key[0..16]).invMixColumns();
            const dfk1 = Block.fromBytes(fixed_key[16..32]).invMixColumns();
            dec_fixed_key[0..16].* = dfk0.toBytes();
            dec_fixed_key[16..32].* = dfk1.toBytes();

            var s0 = Block.fromBytes(state[0..16]);
            var s1 = Block.fromBytes(state[16..32]);
            const rk0 = Block.fromBytes(round_key[0..16]);
            const rk1 = Block.fromBytes(round_key[16..32]);

            s0 = s0.xorBlocks(rk0);
            s1 = s1.xorBlocks(rk1);

            s0 = s0.decrypt(dfk0);
            s1 = s1.decrypt(dfk1);

            var i: usize = steps - 1;
            while (i > 0) : (i -= 1) {
                applyPermutation16(p4_inv, round_key[0..16]);
                applyPermutation16(p5_inv, round_key[16..32]);

                const irk0 = Block.fromBytes(round_key[0..16]);
                const irk1 = Block.fromBytes(round_key[16..32]);
                s0 = s0.decryptLast(irk0);
                s1 = s1.decryptLast(irk1);

                state[0..16].* = s0.toBytes();
                state[16..32].* = s1.toBytes();

                for (0..16) |j| {
                    state[j] ^= round_constants[i - 1][j];
                }

                invMixingLayer256(&state);

                s0 = Block.fromBytes(state[0..16]).invMixColumns();
                s1 = Block.fromBytes(state[16..32]).invMixColumns();

                s0 = s0.decrypt(dfk0);
                s1 = s1.decrypt(dfk1);
            }

            applyPermutation16(p4_inv, round_key[0..16]);
            applyPermutation16(p5_inv, round_key[16..32]);

            const frk0 = Block.fromBytes(round_key[0..16]);
            const frk1 = Block.fromBytes(round_key[16..32]);
            s0 = s0.decryptLast(frk0);
            s1 = s1.decryptLast(frk1);

            out[0..16].* = s0.toBytes();
            out[16..32].* = s1.toBytes();
        }
    };
}

fn Vistrutah512Generic(comptime key_size: KeySize512, comptime round_mode: RoundMode) type {
    return struct {
        const Self = @This();

        /// Block length in bytes.
        pub const block_length = 64;
        /// Key length in bytes.
        pub const key_length = switch (key_size) {
            .key_256 => 32,
            .key_512 => 64,
        };

        const num_rounds = switch (round_mode) {
            .short => switch (key_size) {
                .key_256 => 10,
                .key_512 => 12,
            },
            .long => switch (key_size) {
                .key_256 => 14,
                .key_512 => 18,
            },
        };
        const steps = num_rounds / rounds_per_step;

        /// Encrypt a single block.
        pub fn encrypt(out: *[block_length]u8, in: *const [block_length]u8, key: *const [key_length]u8) void {
            var state: [64]u8 = in.*;
            var fixed_key: [64]u8 = undefined;

            if (key_length == 32) {
                @memcpy(fixed_key[0..32], key);
                @memcpy(fixed_key[32..64], key);
            } else {
                fixed_key = key.*;
            }

            var temp: [32]u8 = undefined;
            @memcpy(&temp, fixed_key[32..64]);
            for (0..32) |i| {
                fixed_key[32 + i] = temp[kexp_shuffle[i]];
            }

            var round_key: [64]u8 = undefined;
            @memcpy(round_key[0..16], fixed_key[16..32]);
            @memcpy(round_key[16..32], fixed_key[0..16]);
            @memcpy(round_key[32..48], fixed_key[48..64]);
            @memcpy(round_key[48..64], fixed_key[32..48]);

            for (0..64) |i| {
                state[i] ^= round_key[i];
            }

            var s0 = Block.fromBytes(state[0..16]);
            var s1 = Block.fromBytes(state[16..32]);
            var s2 = Block.fromBytes(state[32..48]);
            var s3 = Block.fromBytes(state[48..64]);
            const fk0 = Block.fromBytes(fixed_key[0..16]);
            const fk1 = Block.fromBytes(fixed_key[16..32]);
            const fk2 = Block.fromBytes(fixed_key[32..48]);
            const fk3 = Block.fromBytes(fixed_key[48..64]);

            s0 = s0.encrypt(fk0);
            s1 = s1.encrypt(fk1);
            s2 = s2.encrypt(fk2);
            s3 = s3.encrypt(fk3);

            for (1..steps) |i| {
                s0 = s0.encrypt(zero_block);
                s1 = s1.encrypt(zero_block);
                s2 = s2.encrypt(zero_block);
                s3 = s3.encrypt(zero_block);

                state[0..16].* = s0.toBytes();
                state[16..32].* = s1.toBytes();
                state[32..48].* = s2.toBytes();
                state[48..64].* = s3.toBytes();

                mixingLayer512(&state);

                rotateBytes16(round_key[0..16], 5);
                rotateBytes16(round_key[16..32], 10);
                rotateBytes16(round_key[32..48], 5);
                rotateBytes16(round_key[48..64], 10);

                for (0..64) |j| {
                    state[j] ^= round_key[j];
                }

                for (0..16) |j| {
                    state[j] ^= round_constants[i - 1][j];
                }

                s0 = Block.fromBytes(state[0..16]);
                s1 = Block.fromBytes(state[16..32]);
                s2 = Block.fromBytes(state[32..48]);
                s3 = Block.fromBytes(state[48..64]);

                s0 = s0.encrypt(fk0);
                s1 = s1.encrypt(fk1);
                s2 = s2.encrypt(fk2);
                s3 = s3.encrypt(fk3);
            }

            rotateBytes16(round_key[0..16], 5);
            rotateBytes16(round_key[16..32], 10);
            rotateBytes16(round_key[32..48], 5);
            rotateBytes16(round_key[48..64], 10);

            const rk0 = Block.fromBytes(round_key[0..16]);
            const rk1 = Block.fromBytes(round_key[16..32]);
            const rk2 = Block.fromBytes(round_key[32..48]);
            const rk3 = Block.fromBytes(round_key[48..64]);

            s0 = s0.encryptLast(rk0);
            s1 = s1.encryptLast(rk1);
            s2 = s2.encryptLast(rk2);
            s3 = s3.encryptLast(rk3);

            out[0..16].* = s0.toBytes();
            out[16..32].* = s1.toBytes();
            out[32..48].* = s2.toBytes();
            out[48..64].* = s3.toBytes();
        }

        /// Decrypt a single block.
        pub fn decrypt(out: *[block_length]u8, in: *const [block_length]u8, key: *const [key_length]u8) void {
            var state: [64]u8 = in.*;
            var fixed_key: [64]u8 = undefined;

            if (key_length == 32) {
                @memcpy(fixed_key[0..32], key);
                @memcpy(fixed_key[32..64], key);
            } else {
                fixed_key = key.*;
            }

            var temp: [32]u8 = undefined;
            @memcpy(&temp, fixed_key[32..64]);
            for (0..32) |i| {
                fixed_key[32 + i] = temp[kexp_shuffle[i]];
            }

            var round_key: [64]u8 = undefined;
            @memcpy(round_key[0..16], fixed_key[16..32]);
            @memcpy(round_key[16..32], fixed_key[0..16]);
            @memcpy(round_key[32..48], fixed_key[48..64]);
            @memcpy(round_key[48..64], fixed_key[32..48]);

            rotateBytes16(round_key[0..16], (5 * steps) % 16);
            rotateBytes16(round_key[16..32], (10 * steps) % 16);
            rotateBytes16(round_key[32..48], (5 * steps) % 16);
            rotateBytes16(round_key[48..64], (10 * steps) % 16);

            const dfk0 = Block.fromBytes(fixed_key[0..16]).invMixColumns();
            const dfk1 = Block.fromBytes(fixed_key[16..32]).invMixColumns();
            const dfk2 = Block.fromBytes(fixed_key[32..48]).invMixColumns();
            const dfk3 = Block.fromBytes(fixed_key[48..64]).invMixColumns();

            var s0 = Block.fromBytes(state[0..16]);
            var s1 = Block.fromBytes(state[16..32]);
            var s2 = Block.fromBytes(state[32..48]);
            var s3 = Block.fromBytes(state[48..64]);
            var rk0 = Block.fromBytes(round_key[0..16]);
            var rk1 = Block.fromBytes(round_key[16..32]);
            var rk2 = Block.fromBytes(round_key[32..48]);
            var rk3 = Block.fromBytes(round_key[48..64]);

            s0 = s0.xorBlocks(rk0);
            s1 = s1.xorBlocks(rk1);
            s2 = s2.xorBlocks(rk2);
            s3 = s3.xorBlocks(rk3);

            s0 = s0.decrypt(dfk0);
            s1 = s1.decrypt(dfk1);
            s2 = s2.decrypt(dfk2);
            s3 = s3.decrypt(dfk3);

            for (1..steps) |idx| {
                const i = steps - idx;

                rotateBytes16(round_key[0..16], 11);
                rotateBytes16(round_key[16..32], 6);
                rotateBytes16(round_key[32..48], 11);
                rotateBytes16(round_key[48..64], 6);

                rk0 = Block.fromBytes(round_key[0..16]);
                rk1 = Block.fromBytes(round_key[16..32]);
                rk2 = Block.fromBytes(round_key[32..48]);
                rk3 = Block.fromBytes(round_key[48..64]);

                s0 = s0.decryptLast(rk0);
                s1 = s1.decryptLast(rk1);
                s2 = s2.decryptLast(rk2);
                s3 = s3.decryptLast(rk3);

                state[0..16].* = s0.toBytes();
                state[16..32].* = s1.toBytes();
                state[32..48].* = s2.toBytes();
                state[48..64].* = s3.toBytes();

                for (0..16) |j| {
                    state[j] ^= round_constants[i - 1][j];
                }

                invMixingLayer512(&state);

                s0 = Block.fromBytes(state[0..16]).invMixColumns();
                s1 = Block.fromBytes(state[16..32]).invMixColumns();
                s2 = Block.fromBytes(state[32..48]).invMixColumns();
                s3 = Block.fromBytes(state[48..64]).invMixColumns();

                s0 = s0.decrypt(dfk0);
                s1 = s1.decrypt(dfk1);
                s2 = s2.decrypt(dfk2);
                s3 = s3.decrypt(dfk3);
            }

            rotateBytes16(round_key[0..16], 11);
            rotateBytes16(round_key[16..32], 6);
            rotateBytes16(round_key[32..48], 11);
            rotateBytes16(round_key[48..64], 6);

            rk0 = Block.fromBytes(round_key[0..16]);
            rk1 = Block.fromBytes(round_key[16..32]);
            rk2 = Block.fromBytes(round_key[32..48]);
            rk3 = Block.fromBytes(round_key[48..64]);

            s0 = s0.decryptLast(rk0);
            s1 = s1.decryptLast(rk1);
            s2 = s2.decryptLast(rk2);
            s3 = s3.decryptLast(rk3);

            out[0..16].* = s0.toBytes();
            out[16..32].* = s1.toBytes();
            out[32..48].* = s2.toBytes();
            out[48..64].* = s3.toBytes();
        }
    };
}

/// Reverse bits in a byte (for test vector generation).
pub fn reverseBits(byte: u8) u8 {
    var result: u8 = 0;
    var b = byte;
    inline for (0..8) |_| {
        result = (result << 1) | (b & 1);
        b >>= 1;
    }
    return result;
}

const testing = std.testing;

test "Vistrutah-256 encrypt/decrypt roundtrip" {
    const key_256 = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    const key_128 = key_256[0..16].*;

    const plaintext = [_]u8{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    };

    var ciphertext: [32]u8 = undefined;
    var decrypted: [32]u8 = undefined;

    Vistrutah256_256.encrypt(&ciphertext, &plaintext, &key_256);
    Vistrutah256_256.decrypt(&decrypted, &ciphertext, &key_256);
    try testing.expectEqualSlices(u8, &plaintext, &decrypted);

    Vistrutah256_256_Short.encrypt(&ciphertext, &plaintext, &key_256);
    Vistrutah256_256_Short.decrypt(&decrypted, &ciphertext, &key_256);
    try testing.expectEqualSlices(u8, &plaintext, &decrypted);

    Vistrutah256_128.encrypt(&ciphertext, &plaintext, &key_128);
    Vistrutah256_128.decrypt(&decrypted, &ciphertext, &key_128);
    try testing.expectEqualSlices(u8, &plaintext, &decrypted);

    Vistrutah256_128_Short.encrypt(&ciphertext, &plaintext, &key_128);
    Vistrutah256_128_Short.decrypt(&decrypted, &ciphertext, &key_128);
    try testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

test "Vistrutah-512 encrypt/decrypt roundtrip" {
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

    Vistrutah512_256_Short.encrypt(&ciphertext, &plaintext, &key);
    Vistrutah512_256_Short.decrypt(&decrypted, &ciphertext, &key);
    try testing.expectEqualSlices(u8, &plaintext, &decrypted);

    Vistrutah512_256.encrypt(&ciphertext, &plaintext, &key);
    Vistrutah512_256.decrypt(&decrypted, &ciphertext, &key);
    try testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

test "Vistrutah-256 reference vectors" {
    var key: [32]u8 = undefined;
    var plaintext: [32]u8 = undefined;
    for (0..32) |i| {
        key[i] = reverseBits(@truncate(i + 1));
        plaintext[i] = @truncate(i);
    }

    var ciphertext: [32]u8 = undefined;
    var decrypted: [32]u8 = undefined;

    const expected_256_10r = [32]u8{
        0xA9, 0x80, 0x3C, 0xC5, 0x4F, 0x27, 0x74, 0x53,
        0x66, 0xA4, 0xF7, 0xE7, 0x99, 0xA3, 0x4E, 0x24,
        0xF4, 0xC6, 0x9E, 0x37, 0xC2, 0x7E, 0x13, 0xC0,
        0x32, 0xD8, 0x0E, 0xE5, 0x7F, 0x9F, 0xA3, 0x6E,
    };

    Vistrutah256_256_Short.encrypt(&ciphertext, &plaintext, &key);
    try testing.expectEqualSlices(u8, &expected_256_10r, &ciphertext);

    Vistrutah256_256_Short.decrypt(&decrypted, &ciphertext, &key);
    try testing.expectEqualSlices(u8, &plaintext, &decrypted);

    const expected_256_14r = [32]u8{
        0x04, 0x22, 0x7D, 0x3C, 0xD0, 0x0D, 0x1C, 0x7B,
        0xE7, 0xDA, 0x78, 0x6B, 0x8C, 0x88, 0xF9, 0x59,
        0x4E, 0x11, 0x43, 0x17, 0x22, 0x1C, 0x74, 0x30,
        0xB4, 0x7E, 0xD2, 0x1E, 0x8E, 0xB1, 0x5B, 0xBD,
    };

    Vistrutah256_256.encrypt(&ciphertext, &plaintext, &key);
    try testing.expectEqualSlices(u8, &expected_256_14r, &ciphertext);

    Vistrutah256_256.decrypt(&decrypted, &ciphertext, &key);
    try testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

test "Vistrutah-512 reference vectors" {
    var key: [32]u8 = undefined;
    for (0..32) |i| {
        key[i] = reverseBits(@truncate(i + 1));
    }

    var plaintext: [64]u8 = undefined;
    for (0..64) |i| {
        plaintext[i] = @truncate(i);
    }

    var ciphertext: [64]u8 = undefined;
    var decrypted: [64]u8 = undefined;

    const expected_512_10r = [64]u8{
        0x09, 0xC3, 0x87, 0x69, 0x84, 0x35, 0x50, 0x41,
        0xA4, 0x9A, 0xCF, 0x0C, 0xB8, 0x68, 0xE2, 0x64,
        0x58, 0x52, 0x35, 0xE0, 0x58, 0x20, 0x05, 0x5C,
        0x80, 0x8A, 0x3A, 0x03, 0xEA, 0xAE, 0x15, 0x7B,
        0x00, 0x10, 0x0B, 0xC9, 0xB3, 0x01, 0x16, 0x96,
        0xC0, 0xE1, 0xE8, 0x95, 0xE2, 0x16, 0x0C, 0xCC,
        0xEF, 0x31, 0xA3, 0x45, 0x4E, 0x21, 0x6C, 0xA0,
        0x1B, 0xCF, 0x63, 0x66, 0xF5, 0x84, 0xE2, 0x36,
    };

    Vistrutah512_256_Short.encrypt(&ciphertext, &plaintext, &key);
    try testing.expectEqualSlices(u8, &expected_512_10r, &ciphertext);

    Vistrutah512_256_Short.decrypt(&decrypted, &ciphertext, &key);
    try testing.expectEqualSlices(u8, &plaintext, &decrypted);

    const expected_512_14r = [64]u8{
        0xA8, 0x75, 0xE9, 0xF9, 0x13, 0x0B, 0xE6, 0x8B,
        0x68, 0x67, 0xCB, 0x66, 0xF4, 0x03, 0x18, 0xEC,
        0x7E, 0x16, 0xA3, 0xA0, 0x50, 0x16, 0x51, 0xFF,
        0xF3, 0xBE, 0x08, 0xFE, 0x70, 0xB3, 0xC7, 0x96,
        0x0D, 0x9B, 0x1A, 0x83, 0x44, 0xC9, 0xEB, 0x61,
        0xC2, 0xBF, 0xCB, 0xF2, 0xF6, 0x02, 0x8E, 0x1F,
        0xCD, 0x94, 0x6B, 0xFF, 0xC9, 0x5B, 0xB4, 0x2F,
        0x9E, 0x0E, 0x87, 0x61, 0x75, 0x83, 0x19, 0xE3,
    };

    Vistrutah512_256.encrypt(&ciphertext, &plaintext, &key);
    try testing.expectEqualSlices(u8, &expected_512_14r, &ciphertext);

    Vistrutah512_256.decrypt(&decrypted, &ciphertext, &key);
    try testing.expectEqualSlices(u8, &plaintext, &decrypted);
}

test "mixing layer 256" {
    var state = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
    const original = state;

    mixingLayer256(&state);
    invMixingLayer256(&state);

    try testing.expectEqualSlices(u8, &original, &state);
}

test "mixing layer 512" {
    var state: [64]u8 = undefined;
    for (0..64) |i| {
        state[i] = @truncate(i);
    }
    const original = state;

    mixingLayer512(&state);
    invMixingLayer512(&state);

    try testing.expectEqualSlices(u8, &original, &state);
}
