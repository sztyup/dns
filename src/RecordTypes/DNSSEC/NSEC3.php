<?php

declare(strict_types=1);

namespace Sztyup\Dns\RecordTypes\DNSSEC;

use Sztyup\Dns\DnsConstants;
use Sztyup\Dns\RecordTypes\ResourceRecord;
use Sztyup\Dns\Utilities\BinaryString;
use Sztyup\Dns\Utilities\DataFormats;
use Sztyup\Dns\Utilities\StringStream;

use function ord;
use function strlen;

class NSEC3 extends NSEC
{
    private const FLAG_OPT_OUT = 0b00000001;

    public int $hashAlgorithm;

    public bool $optOut;

    public int $iterations;

    public string $salt;

    public string $nextHashedOwnerName;

    protected function parseData(StringStream $stream, int $length): void
    {
        $end = $stream->tell() + $length;

        $this->hashAlgorithm = $stream->readUInt8();

        $flags        = $stream->readUInt8();
        $this->optOut = (bool)($flags & self::FLAG_OPT_OUT);

        $this->iterations = $stream->readUInt16();

        $saltLength = $stream->readUInt8();
        $this->salt = $stream->read($saltLength);

        $hashLength                = $stream->readUInt8();
        $this->nextHashedOwnerName = $stream->read($hashLength);

        $this->types = $this->parseBitmaps($stream, $end);
    }

    protected function wireData(): BinaryString
    {
        $string = new BinaryString();

        $string->writeUInt8($this->hashAlgorithm);

        $string->writeUInt8($this->getFlagsValue());

        $string->writeUInt16($this->iterations);

        $string->writeUInt8(strlen($this->salt));
        $string->append($this->salt);

        $string->writeUInt8(strlen($this->nextHashedOwnerName));
        $string->append($this->nextHashedOwnerName);

        $string->append($this->writeBitmaps($this->types));

        return $string;
    }

    protected function getFlagsValue(): int
    {
        $flags = 0;

        if ($this->optOut) {
            $flags |= $this->optOut;
        }

        return $flags;
    }

    protected function getTextRepresentation(): string
    {
        return sprintf(
            '%d %d %d %s %s %s',
            $this->hashAlgorithm,
            $this->getFlagsValue(),
            $this->iterations,
            empty($this->salt) ? '-' : strtoupper(bin2hex($this->salt)),
            DataFormats::base32encode($this->nextHashedOwnerName),
            implode(' ', $this->getTypeNames())
        );
    }

    public static function getId(): int
    {
        return 50;
    }

    public static function getDescription(): string
    {
        return 'NSEC3';
    }
}
