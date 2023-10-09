// These initial hash values were obtained by taking the first 32 bits
// of the fractional parts of the square roots of the first
// eight prime numbers. They are hardcoded and have been
// defined by NIST (https://csrc.nist.gov/pubs/fips/180-4/upd1/final).
pub const H_0: &'static str = "6a09e667";
pub const H_1: &'static str = "bb67ae85";
pub const H_2: &'static str = "3c6ef372";
pub const H_3: &'static str = "a54ff53a";
pub const H_4: &'static str = "510e527f";
pub const H_5: &'static str = "9b05688c";
pub const H_6: &'static str = "1f83d9ab";
pub const H_7: &'static str = "5be0cd19";

// A set of constants (k) which will be used to mix
// into the hex digest. They are the first 32 bits of
// the fractional parts  of the cubic roots of the first
// 64 prime numbers. They are hardcoded and have been
// defined by NIST (https://csrc.nist.gov/pubs/fips/180-4/upd1/final).
pub const K: [&'static str; 64] = [
    "0x428a2f98",
    "0x71374491",
    "0xb5c0fbcf",
    "0xe9b5dba5",
    "0x3956c25b",
    "0x59f111f1",
    "0x923f82a4",
    "0xab1c5ed5",
    "0xd807aa98",
    "0x12835b01",
    "0x243185be",
    "0x550c7dc3",
    "0x72be5d74",
    "0x80deb1fe",
    "0x9bdc06a7",
    "0xc19bf174",
    "0xe49b69c1",
    "0xefbe4786",
    "0x0fc19dc6",
    "0x240ca1cc",
    "0x2de92c6f",
    "0x4a7484aa",
    "0x5cb0a9dc",
    "0x76f988da",
    "0x983e5152",
    "0xa831c66d",
    "0xb00327c8",
    "0xbf597fc7",
    "0xc6e00bf3",
    "0xd5a79147",
    "0x06ca6351",
    "0x14292967",
    "0x27b70a85",
    "0x2e1b2138",
    "0x4d2c6dfc",
    "0x53380d13",
    "0x650a7354",
    "0x766a0abb",
    "0x81c2c92e",
    "0x92722c85",
    "0xa2bfe8a1",
    "0xa81a664b",
    "0xc24b8b70",
    "0xc76c51a3",
    "0xd192e819",
    "0xd6990624",
    "0xf40e3585",
    "0x106aa070",
    "0x19a4c116",
    "0x1e376c08",
    "0x2748774c",
    "0x34b0bcb5",
    "0x391c0cb3",
    "0x4ed8aa4a",
    "0x5b9cca4f",
    "0x682e6ff3",
    "0x748f82ee",
    "0x78a5636f",
    "0x84c87814",
    "0x8cc70208",
    "0x90befffa",
    "0xa4506ceb",
    "0xbef9a3f7",
    "0xc67178f2",
];
