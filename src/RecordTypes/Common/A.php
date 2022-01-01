<?php

declare(strict_types=1);

namespace Sztyup\Dns\RecordTypes\Common;

use IPLib\Address\IPv4;
use Sztyup\Dns\RecordTypes\ResourceRecord;
use Sztyup\Dns\Utilities\BinaryString;
use Sztyup\Dns\Utilities\StringStream;

class A extends ResourceRecord
{
    public IPv4 $ip;

    protected function parseData(StringStream $stream, int $length): void
    {
        $this->ip = IPv4::fromBytes($stream->readByteArray(4));
    }

    protected function wireData(): BinaryString
    {
        $string = new BinaryString();

        $string->writeBytes($this->ip->getBytes());

        return $string;
    }

    protected function getTextRepresentation(): string
    {
        return $this->ip->toString();
    }

    public static function getId(): int
    {
        return 1;
    }
}
