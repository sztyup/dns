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

class NSEC extends ResourceRecord
{
    public string $nextDomainName;

    public array $types;

    protected function parseData(StringStream $stream, int $length): void
    {
        $end = $stream->tell() + $length;

        $this->nextDomainName = DataFormats::readDomainName($stream);

        $this->types = $this->parseBitmaps($stream, $end);
    }

    protected function wireData(): BinaryString
    {
        $data = new BinaryString();

        $data->append(DataFormats::writeDomainName($this->nextDomainName));
        $data->append($this->writeBitmaps($this->types));

        return $data;
    }

    protected function parseBitmaps(StringStream $stream, int $end): array
    {
        $types = [];
        while ($stream->tell() < $end) {
            $window       = $stream->readUInt8();
            $bitmapLength = $stream->readUInt8();
            $bitmap       = $stream->read($bitmapLength);

            $types[] = $this->parseBitmap($window, $bitmap);
        }

        return array_merge([], ...$types);
    }

    protected function writeBitmaps(array $types): BinaryString
    {
        $string = new BinaryString();

        foreach ($this->createBitmap($types) as $window => $bitmap) {
            $string->writeUInt8($window);
            $string->writeUInt8(strlen($bitmap));
            $string->append($bitmap);
        }

        return $string;
    }

    private function parseBitmap(int $window, string $bitmap): array
    {
        $array = [];

        $length = strlen($bitmap);
        for ($i = 0; $i < $length; $i++) {
            for ($bit = 0; $bit < 8; $bit++) {
                if (ord($bitmap[$i]) & (1 << (7 - $bit))) {
                    $array[] = $window * 256 + ($bit + $i * 8);
                }
            }
        }

        return $array;
    }

    private function createBitmap(array $types): array
    {
        $array = [];

        foreach ($types as $type) {
            $window = (int)floor($type / 256);
            $int    = $type % 256;
            $char   = (int)floor($int / 8);
            $bit    = $int % 8;

            $array[$window]        ??= array_fill(0, 8, 0);
            $array[$window][$char] |= 1 << (7 - $bit);
        }

        foreach ($array as $window => $bits) {
            $array[$window] = rtrim(implode('', array_map('chr', $bits)), "\x00");
        }

        return $array;
    }

    protected function getTypeNames(): array
    {
        $names = [];

        foreach ($this->types as $type) {
            $names[] = DnsConstants::getRecordName($type);
        }

        return $names;
    }

    protected function getTextRepresentation(): string
    {
        return sprintf('%s %s', $this->nextDomainName, implode(' ', $this->getTypeNames()));
    }

    public static function getId(): int
    {
        return 47;
    }
}
