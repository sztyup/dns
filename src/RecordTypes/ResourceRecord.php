<?php

declare(strict_types=1);

namespace Sztyup\Dns\RecordTypes;

use RuntimeException;
use Sztyup\Dns\DnsConstants;
use Sztyup\Dns\HasWireFormat;
use Sztyup\Dns\Utilities\BinaryString;
use Sztyup\Dns\Utilities\DataFormats;
use Sztyup\Dns\Utilities\StringStream;

use function strlen;

abstract class ResourceRecord implements HasWireFormat
{
    public function __construct(public string $name, public int $class, public int $ttl)
    {
    }

    public static function fromWireFormat(StringStream $stream, int $length): static
    {
        $name       = DataFormats::readDomainName($stream);
        $type       = DnsConstants::RECORD_TYPES[$stream->readUInt16()];
        $class      = $stream->readUInt16();
        $ttl        = $stream->readUInt32();
        $dataLength = $stream->readUInt16();
        $end        = $stream->tell() + $dataLength;

        $record = new $type($name, $class, $ttl);
        $record->parseData($stream, $dataLength);

        if ($stream->tell() !== $end) {
            throw new RuntimeException('Invalid message'); // RDATA processing went over the length of RDATA or skipped
//            $stream->seek($end);
        }

        return $record;
    }

    public function toWireFormat(): BinaryString
    {
        $query = new BinaryString();

        $query->append(DataFormats::writeDomainName($this->name)); // NAME

        $query->writeUInt16(static::getId()); // TYPE

        $query->writeUInt16($this->class); // CLASS (UDP payload size)

        $query->writeUInt32($this->ttl); // TTL

        $data = $this->wireData()->toString();

        $query->writeUInt16(strlen($data));

        $query->append($data);

        return $query;
    }

    public function getCanonicalRepresentation(int $originalTTL): string
    {
        $string = new BinaryString();

        $string->append(DataFormats::writeDomainName(strtolower($this->name)));

        $string->writeUInt16(static::getId());

        $string->writeUInt16($this->class);

        $string->writeUInt32($originalTTL);

        $data = $this->getCanonicalData()->toString();

        $string->writeUInt16(strlen($data));

        $string->append($data);

        return $string->toString();
    }

    public function __toString(): string
    {
        return sprintf(
            '%s. %s %s %s',
            $this->name,
            DnsConstants::CLASSES[$this->class],
            static::getName(),
            $this->getTextRepresentation()
        );
    }

    public static function getName(): string
    {
        $path = explode('\\', static::class);

        return array_pop($path);
    }

    abstract protected function parseData(StringStream $stream, int $length): void;

    abstract protected function wireData(): BinaryString;

    public function getCanonicalData(): BinaryString
    {
        return $this->wireData();
    }

    abstract protected function getTextRepresentation(): string;

    abstract public static function getId(): int;

    abstract public static function getDescription(): string;
}
