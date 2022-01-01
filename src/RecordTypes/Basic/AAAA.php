<?php

declare(strict_types=1);

namespace Sztyup\Dns\RecordTypes\Basic;

use IPLib\Address\IPv6;
use Sztyup\Dns\RecordTypes\ResourceRecord;
use Sztyup\Dns\Utilities\BinaryString;
use Sztyup\Dns\Utilities\StringStream;

class AAAA extends ResourceRecord
{
    public IPv6 $ip;

    protected function parseData(StringStream $stream, int $length): void
    {
        $this->ip = IPv6::fromBytes($stream->readByteArray(16));
    }

    protected function wireData(): BinaryString
    {
        $data = new BinaryString();

        $data->writeBytes($this->ip->getBytes());

        return $data;
    }

    public static function getId(): int
    {
        return 28;
    }

    public static function getDescription(): string
    {
        return 'IP6 Address';
    }

    protected function getTextRepresentation(): string
    {
        return $this->ip->toString();
    }
}
