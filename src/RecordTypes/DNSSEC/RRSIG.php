<?php

declare(strict_types=1);

namespace Sztyup\Dns\RecordTypes\DNSSEC;

use DateTime;
use DateTimeInterface;
use Sztyup\Dns\DnsConstants;
use Sztyup\Dns\RecordTypes\ResourceRecord;
use Sztyup\Dns\Utilities\BinaryString;
use Sztyup\Dns\Utilities\DataFormats;
use Sztyup\Dns\Utilities\StringStream;

class RRSIG extends ResourceRecord
{
    public int $typeCovered;

    public int $algorithm;

    public int $labels;

    public int $originalTTL;

    public DateTime $signatureExpiration;

    public DateTime $signatureInception;

    public int $keyTag;

    public string $signerName;

    public string $signature;

    protected function parseData(StringStream $stream, int $length): void
    {
        $start = $stream->tell();

        $this->typeCovered         = $stream->readUInt16();
        $this->algorithm           = $stream->readUInt8();
        $this->labels              = $stream->readUInt8();
        $this->originalTTL         = $stream->readUInt32();
        $this->signatureExpiration = new DateTime('@' . $stream->readUInt32());
        $this->signatureInception  = new DateTime('@' . $stream->readUInt32());
        $this->keyTag              = $stream->readUInt16();

        $this->signerName = DataFormats::readDomainName($stream);

        $this->signature = $stream->read(($start + $length) - $stream->tell());
    }

    protected function wireData(): BinaryString
    {
        $canonical = $this->getCanonicalData();

        $canonical->append($this->signature);

        return $canonical;
    }

    public function getCanonicalData(): BinaryString
    {
        $string = new BinaryString();

        $string->writeUInt16($this->typeCovered);
        $string->writeUInt8($this->algorithm);
        $string->writeUInt8($this->labels);
        $string->writeUInt32($this->originalTTL);
        $string->writeUInt32($this->signatureExpiration->getTimestamp());
        $string->writeUInt32($this->signatureInception->getTimestamp());
        $string->writeUInt16($this->keyTag);

        $string->append(DataFormats::writeDomainName($this->signerName));

        return $string;
    }

    public function matchingKey(DNSKEY $dnskey): bool
    {
        return $this->signerName === $dnskey->name &&
            $this->algorithm === $dnskey->algorithm &&
            $this->keyTag === $dnskey->calculateKeyTag() &&
            $dnskey->zoneKey === true;
    }

    public function matchingRecord(ResourceRecord $record): bool
    {
        if ((substr_count($record->name, '.') + 1) < $this->labels) {
            return false;
        }

        if ($this->typeCovered !== $record->getActualId()) {
            return false;
        }

        if ($this->class !== $record->class) {
            return false;
        }

        if ($this->name !== $record->name) {
            return false;
        }

        return true;
    }

    public function validForTime(DateTimeInterface $dateTime): bool
    {
        return $this->signatureExpiration >= $dateTime &&
            $this->signatureInception <= $dateTime;
    }

    protected function getTextRepresentation(): string
    {
        return sprintf('%s', DnsConstants::getRecordName($this->typeCovered));
    }

    public static function getId(): int
    {
        return 46;
    }
}
