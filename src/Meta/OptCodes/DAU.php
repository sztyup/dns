<?php

declare(strict_types=1);

namespace Sztyup\Dns\Meta\OptCodes;

class DAU extends RFC6975
{
    // Name, Mnemonic, Zone signing, Transaction security
    public const ALGORITHMS = [
        0  => ['Delete DS', 'DELETE', false, false,],
        1  => ['"RSA/MD5 (deprecated, see 5)"', 'RSAMD5', false, true,],
        2  => ['Diffie-Hellman', 'DH', false, true,],
        3  => ['DSA/SHA1', 'DSA', true, true,],
        5  => ['RSA/SHA-1', 'RSASHA1', true, true,],
        6  => ['DSA-NSEC3-SHA1', 'DSA-NSEC3-SHA1', true, true,],
        7  => ['RSASHA1-NSEC3-SHA1', 'RSASHA1-NSEC3-SHA1', true, true,],
        8  => ['RSA/SHA-256', 'RSASHA256', true, false,],
        10 => ['RSA/SHA-512', 'RSASHA512', true, false,],
        12 => ['GOST R 34.10-2001', 'ECC-GOST', true, false,],
        13 => ['ECDSA Curve P-256 with SHA-256', 'ECDSAP256SHA256', true, false,],
        14 => ['ECDSA Curve P-384 with SHA-384', 'ECDSAP384SHA384', true, false,],
        15 => ['Ed25519', 'ED25519', true, false,],
        16 => ['Ed448', 'ED448', true, false,],
    ];
}
