<?php

declare(strict_types=1);

namespace Sztyup\Dns\RecordTypes\Basic;

use Sztyup\Dns\RecordTypes\ResourceRecord;
use Sztyup\Dns\Utilities\BinaryString;
use Sztyup\Dns\Utilities\DataFormats;
use Sztyup\Dns\Utilities\StringStream;

class NS extends ResourceRecord
{
    public string $domain;

    protected function parseData(StringStream $stream, int $length): void
    {
        $this->domain = DataFormats::readDomainName($stream);
    }

    protected function wireData(): BinaryString
    {
        return new BinaryString(DataFormats::writeDomainName($this->domain));
    }

    public static function getId(): int
    {
        return 2;
    }

    public static function getDescription(): string
    {
        return 'an authoritative name server';
    }

    protected function getTextRepresentation(): string
    {
        return $this->domain;
    }
}
