<?php

declare(strict_types=1);

namespace Sztyup\Dns\RecordTypes\DNSSEC;

use Sztyup\Dns\DnsConstants;
use Sztyup\Dns\RecordTypes\ResourceRecord;
use Sztyup\Dns\Utilities\BinaryString;
use Sztyup\Dns\Utilities\StringStream;

class DS extends ResourceRecord
{
    public int $keyTag;

    public int $algorithm;

    public int $digestType;

    public string $digest;

    public static function create(int $keyTag, int $algorithm, int $digestType, string $digest): DS
    {
        $new = new self('', DnsConstants::CLASS_IN, 300);

        $new->keyTag     = $keyTag;
        $new->algorithm  = $algorithm;
        $new->digestType = $digestType;
        $new->digest     = $digest;

        return $new;
    }

    public function matchingKey(DNSKEY $dnskey): bool
    {
        if ($dnskey->name !== $this->name) {
            return false;
        }

        if ($dnskey->calculateKeyTag() !== $this->keyTag) {
            return false;
        }

        return true;
    }

    protected function parseData(StringStream $stream, int $length): void
    {
        $this->keyTag     = $stream->readUInt16();
        $this->algorithm  = $stream->readUInt8();
        $this->digestType = $stream->readUInt8();

        $this->digest = $stream->read($length - 4);
    }

    protected function wireData(): BinaryString
    {
        $data = new BinaryString();

        $data->writeUInt16($this->keyTag);
        $data->writeUInt8($this->algorithm);
        $data->writeUInt8($this->digestType);
        $data->append($this->digest);

        return $data;
    }

    protected function getTextRepresentation(): string
    {
        return sprintf(
            '%d %d %d ( %s )',
            $this->keyTag,
            $this->algorithm,
            $this->digestType,
            base64_encode($this->digest)
        );
    }

    public static function getId(): int
    {
        return 43;
    }

    public static function getDescription(): string
    {
        return 'Delegation Signer';
    }
}
