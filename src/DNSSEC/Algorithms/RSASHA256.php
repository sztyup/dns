<?php

declare(strict_types=1);

namespace Sztyup\Dns\DNSSEC\Algorithms;

class RSASHA256 extends RSASHA
{
    public static function getID(): int
    {
        return 8;
    }

    protected function getHash(): string
    {
        return 'sha256';
    }
}
