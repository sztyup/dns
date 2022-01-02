<?php

declare(strict_types=1);

namespace Sztyup\Dns\DNSSEC\Algorithms;

use phpseclib3\Crypt\Common\PublicKey;
use phpseclib3\Crypt\RSA;
use RuntimeException;

class RSASHA256 extends RSASHA
{
    public function toPublicKey(): PublicKey
    {
        $key = RSA::loadParameters([
            'modulus'  => $this->modulus,
            'exponent' => $this->exponent,
        ]);

        if (!$key instanceof RSA) {
            throw new RuntimeException('Cannot create RSA key');
        }

        return $key->withHash('sha256')
            ->withPadding(RSA::SIGNATURE_PKCS1);
    }

    public static function getID(): int
    {
        return 8;
    }
}
