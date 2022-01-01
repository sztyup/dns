<?php

declare(strict_types=1);

namespace Sztyup\Dns\RecordTypes\Basic;

use Sztyup\Dns\RecordTypes\ResourceRecord;
use Sztyup\Dns\Utilities\BinaryString;
use Sztyup\Dns\Utilities\DataFormats;
use Sztyup\Dns\Utilities\StringStream;

class MX extends ResourceRecord
{
    public int $preference;

    public string $exchange;

    protected function parseData(StringStream $stream, int $length): void
    {
        $this->preference = $stream->readUInt16();
        $this->exchange   = DataFormats::readDomainName($stream);
    }

    protected function wireData(): BinaryString
    {
        $data = new BinaryString();

        $data->writeUInt16($this->preference);
        $data->append(DataFormats::writeDomainName($this->exchange));

        return $data;
    }

    public static function getId(): int
    {
        return 15;
    }

    public static function getDescription(): string
    {
        return 'mail exchange';
    }

    protected function getTextRepresentation(): string
    {
        return $this->preference . ' ' . $this->exchange;
    }
}
