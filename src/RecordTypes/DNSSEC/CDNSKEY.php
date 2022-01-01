<?php

declare(strict_types=1);

namespace Sztyup\Dns\RecordTypes\DNSSEC;

use Sztyup\Dns\RecordTypes\ResourceRecord;
use Sztyup\Dns\Utilities\BinaryString;
use Sztyup\Dns\Utilities\StringStream;

class CDNSKEY extends DNSKEY
{
    public static function getId(): int
    {
        return 60;
    }

    public static function getDescription(): string
    {
        return 'DNSKEY(s) the Child wants reflected in DS';
    }
}
