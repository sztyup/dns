<?php

declare(strict_types=1);

namespace Sztyup\Dns\DNSSEC\Algorithms;

use phpseclib3\Crypt\Common\PublicKey;

interface Algorithm
{
    public function toPublicKey(): PublicKey;

    public static function getID(): int;
}
