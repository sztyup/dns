<?php

declare(strict_types=1);

namespace Sztyup\Dns\RecordTypes;

use RuntimeException;
use Sztyup\Dns\Utilities\BinaryString;
use Sztyup\Dns\Utilities\DataFormats;
use Sztyup\Dns\Utilities\StringStream;

class DNSKEY extends ResourceRecord
{
    private const FLAG_ZONE_KEY          = 0b0000000100000000;
    private const FLAG_SECURE_ENTRYPOINT = 0b0000000000000001;

    public bool $zoneKey;

    public bool $secureEntrypoint;

    public int $algorithm;

    public string $key;

    public int $keyTag;

    public function getDigestString(): string
    {
        return DataFormats::writeDomainName($this->name) . $this->wireData();
    }

    protected function parseData(StringStream $stream, int $length): void
    {
        $flags = $stream->readUInt16();

        $this->zoneKey          = (bool)($flags & self::FLAG_ZONE_KEY);
        $this->secureEntrypoint = (bool)($flags & self::FLAG_SECURE_ENTRYPOINT);

        $protocol = $stream->readUInt8();

        if ($protocol !== 3) {
            throw new RuntimeException('Invalid DNSKEY record');
        }

        $this->algorithm = $stream->readUInt8();

        $this->key = $stream->read($length - 4);

        $keyTag       = $flags + ($protocol << 8) + $this->algorithm;
        $keyTag       += array_sum(unpack('n*', $this->key));
        $keyTag       += ($keyTag >> 16) & 0xFFFF;
        $this->keyTag = $keyTag & 0xFFFF;
    }

    protected function wireData(): BinaryString
    {
        $string = new BinaryString();

        $flags = 0;
        if ($this->zoneKey) {
            $flags |= self::FLAG_ZONE_KEY;
        }

        if ($this->secureEntrypoint) {
            $flags |= self::FLAG_SECURE_ENTRYPOINT;
        }

        $string->writeUInt16($flags);
        $string->writeUInt8(3); // Protocol
        $string->writeUInt8($this->algorithm);
        $string->append($this->key);

        return $string;
    }

    public static function getId(): int
    {
        return 48;
    }

    public static function getDescription(): string
    {
        return 'DNSKEY';
    }

    protected function getTextRepresentation(): string
    {
        throw new RuntimeException('TODO'); // TODO
    }
}
