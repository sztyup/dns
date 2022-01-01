<?php

declare(strict_types=1);

namespace Sztyup\Dns\RecordTypes\Common;

use Sztyup\Dns\RecordTypes\ResourceRecord;
use Sztyup\Dns\Utilities\BinaryString;
use Sztyup\Dns\Utilities\DataFormats;
use Sztyup\Dns\Utilities\StringStream;

class CNAME extends ResourceRecord
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

    protected function getTextRepresentation(): string
    {
        return $this->domain;
    }

    public static function getId(): int
    {
        return 5;
    }
}
