const unsigned char shellcode[369] = {
    0x55,0x8b,0xec,0x83,0xec,0x44,0x56,0x57,0x8d,0x4d,0xcc,0xc7,0x45,0xcc,0x4c,0x6f,0x61,0x64,0xc7,0x45,0xd0,0x4c,0x69,0x62,0x72,0xc7,0x45,0xd4,0x61,0x72,0x79,0x41,
    0xc6,0x45,0xd8,0,0xc7,0x45,0xe8,0x4d,0x65,0x73,0x73,0xc7,0x45,0xec,0x61,0x67,0x65,0x42,0xc7,0x45,0xf0,0x6f,0x78,0x41,0,0xc7,0x45,0xdc,0x68,0x65,0x6c,0x6c,
    0xc7,0x45,0xe0,0x6f,0x20,0x77,0x6f,0xc7,0x45,0xe4,0x72,0x6c,0x64,0,0xc7,0x45,0xf4,0x75,0x73,0x65,0x72,0xc7,0x45,0xf8,0x33,0x32,0x2e,0x64,0x66,0xc7,0x45,0xfc,
    0x6c,0x6c,0xc6,0x45,0xfe,0,0xc7,0x45,0xbc,0x47,0x65,0x74,0x50,0xc7,0x45,0xc0,0x72,0x6f,0x63,0x41,0xc7,0x45,0xc4,0x64,0x64,0x72,0x65,0x66,0xc7,0x45,0xc8,0x73,
    0x73,0xc6,0x45,0xca,0,0xe8,0x36,0,0,0,0x8d,0x4d,0xbc,0x8b,0xf8,0xe8,0x2c,0,0,0,0x8b,0xf0,0x8d,0x45,0xe8,0x50,0x8d,0x45,0xf4,0x50,0xff,0xd7,
    0x50,0xff,0xd6,0x6a,0,0x6a,0,0x8d,0x4d,0xdc,0x51,0x6a,0,0xff,0xd0,0x5f,0x5e,0x8b,0xe5,0x5d,0xc3,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,
    0x55,0x8b,0xec,0x83,0xec,0x14,0x53,0x56,0x8b,0xd1,0xc7,0x45,0xfc,0,0,0,0,0x57,0x89,0x55,0xf4,0x64,0xa1,0x30,0,0,0,0x8b,0x40,0xc,0x8b,0x40,
    0x14,0x8b,0,0x8b,0,0x8b,0x40,0x10,0x89,0x45,0xfc,0x8b,0x7d,0xfc,0x33,0xf6,0x8b,0x47,0x3c,0x8b,0x44,0x38,0x78,0x8b,0x4c,0x38,0x1c,0x8b,0x5c,0x38,0x24,0x3,
    0xcf,0x3,0xdf,0x89,0x4d,0xec,0x8b,0x4c,0x38,0x20,0x3,0xcf,0x89,0x5d,0xf0,0x8b,0x5c,0x38,0x18,0x89,0x4d,0xf8,0x85,0xdb,0x74,0x38,0x66,0xf,0x1f,0x44,0,0,
    0x8b,0x4,0xb1,0x8a,0xc,0x38,0x3,0xc7,0x84,0xc9,0x74,0x11,0xf,0x1f,0x40,0,0x3a,0xa,0x75,0x9,0x8a,0x48,0x1,0x40,0x42,0x84,0xc9,0x75,0xf3,0xf,0xb6,0xa,
    0xf,0xb6,0,0x2b,0xc1,0x74,0x14,0x8b,0x4d,0xf8,0x46,0x8b,0x55,0xf4,0x3b,0xf3,0x72,0xce,0x5f,0x5e,0x33,0xc0,0x5b,0x8b,0xe5,0x5d,0xc3,0x8b,0x45,0xf0,0x8b,0x4d,
    0xec,0xf,0xb7,0x4,0x70,0x8b,0x4,0x81,0x3,0xc7,0x5f,0x5e,0x5b,0x8b,0xe5,0x5d,0xc3,
};