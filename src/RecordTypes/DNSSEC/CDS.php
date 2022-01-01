<?php

declare(strict_types=1);

namespace Sztyup\Dns\RecordTypes\DNSSEC;

class CDS extends DS
{
    public static function getId(): int
    {
        return 59;
    }
}
