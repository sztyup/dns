<?php

declare(strict_types=1);

namespace Sztyup\Dns\DNSSEC\Algorithms;

class RSASHA1 extends RSASHA
{
    public static function getID(): int
    {
        return 5;
    }

    protected function getHash(): string
    {
        return 'sha1';
    }
}
