<?php

declare(strict_types=1);

namespace Sztyup\Dns\RecordTypes\DNSSEC;

use Sztyup\Dns\RecordTypes\ResourceRecord;
use Sztyup\Dns\Utilities\BinaryString;
use Sztyup\Dns\Utilities\StringStream;

use function strlen;

class NSEC3PARAM extends ResourceRecord
{
    public int $hashAlgorithm;

    public int $iterations;

    public string $salt;

    protected function parseData(StringStream $stream, int $length): void
    {
        $this->hashAlgorithm = $stream->readUInt8();

        $stream->readUInt8(); // flags, currently all zero

        $this->iterations = $stream->readUInt16();

        $saltLength = $stream->readUInt8();
        $this->salt = $stream->read($saltLength);
    }

    protected function wireData(): BinaryString
    {
        $string = new BinaryString();

        $string->writeUInt8($this->hashAlgorithm);

        $string->writeUInt8(0); // flags, currently all zero

        $string->writeUInt16($this->iterations);

        $string->writeUInt8(strlen($this->salt));
        $string->append($this->salt);

        return $string;
    }

    protected function getTextRepresentation(): string
    {
        return sprintf(
            '%d %d %d %s',
            $this->hashAlgorithm,
            0,
            $this->iterations,
            empty($this->salt) ? '-' : strtoupper(bin2hex($this->salt)),
        );
    }

    public static function getId(): int
    {
        return 51;
    }
}
