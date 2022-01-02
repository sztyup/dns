<?php

declare(strict_types=1);

namespace Sztyup\Dns\RecordTypes\DNSSEC;

class CDNSKEY extends DNSKEY
{
    public static function getId(): int
    {
        return 60;
    }
}
