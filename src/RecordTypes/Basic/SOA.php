<?php

declare(strict_types=1);

namespace Sztyup\Dns\RecordTypes\Basic;

use Sztyup\Dns\RecordTypes\ResourceRecord;
use Sztyup\Dns\Utilities\BinaryString;
use Sztyup\Dns\Utilities\DataFormats;
use Sztyup\Dns\Utilities\StringStream;

class SOA extends ResourceRecord
{
    public string $mName;

    public string $rName;

    public int $serial;

    public int $refresh;

    public int $retry;

    public int $expire;

    public int $minimum;

    protected function parseData(StringStream $stream, int $length): void
    {
        $this->mName   = DataFormats::readDomainName($stream);
        $this->rName   = DataFormats::readDomainName($stream);
        $this->serial  = $stream->readUInt32();
        $this->refresh = $stream->readUInt32();
        $this->retry   = $stream->readUInt32();
        $this->expire  = $stream->readUInt32();
        $this->minimum = $stream->readUInt32();
    }

    protected function wireData(): BinaryString
    {
        $string = new BinaryString();

        $string->append(DataFormats::writeDomainName($this->mName));
        $string->append(DataFormats::writeDomainName($this->rName));
        $string->writeUInt32($this->serial);
        $string->writeUInt32($this->refresh);
        $string->writeUInt32($this->retry);
        $string->writeUInt32($this->expire);
        $string->writeUInt32($this->minimum);

        return $string;
    }

    public static function getId(): int
    {
        return 6;
    }

    public static function getDescription(): string
    {
        return 'marks the start of a zone of authority';
    }

    protected function getTextRepresentation(): string
    {
        return sprintf(
            '%s %s (%d %d %d %d %d)',
            $this->mName,
            $this->rName,
            $this->serial,
            $this->refresh,
            $this->retry,
            $this->expire,
            $this->minimum
        );
    }
}
