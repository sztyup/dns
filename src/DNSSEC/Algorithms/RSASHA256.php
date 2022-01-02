<?php

declare(strict_types=1);

namespace Sztyup\Dns\DNSSEC\Algorithms;

use phpseclib3\Crypt\Common\PublicKey;
use phpseclib3\Crypt\RSA;

class RSASHA256 extends RSASHA
{
    public function toPublicKey(): PublicKey
    {
        return RSA::loadPublicKey([
            'modulus'  => $this->modulus,
            'exponent' => $this->exponent,
        ])
            ->withHash('sha256')
            ->withPadding(RSA::SIGNATURE_PKCS1);
    }

    public static function getID(): int
    {
        return 8;
    }
}
