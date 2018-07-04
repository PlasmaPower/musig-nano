# musig-nano

This is a Rust project that exports a C FFI which is documented in `interface.h`. It allows for N of N multisignature accounts with Nano.

Details of MuSig can be found here: https://blockstream.com/2018/01/23/musig-key-aggregation-schnorr-signatures.html

This library does require the R value commitment, because there is no proof for the scheme without it. See https://eprint.iacr.org/2018/068 for more details.
