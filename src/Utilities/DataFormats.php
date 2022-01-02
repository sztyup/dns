<?php

declare(strict_types=1);

namespace Sztyup\Dns\Utilities;

use DateTime;
use Exception;
use RuntimeException;

use function strlen;

class DataFormats
{
    public static function domainChain(string $domain): array
    {
        $labels = explode('.', $domain);
        $chain  = [$domain];
        do {
            array_shift($labels);
            $chain[] = implode('.', $labels);
        } while (!empty($labels));

        krsort($chain);

        return $chain;
    }

    public static function writeDomainName(string $domainName): BinaryString
    {
        $string = new BinaryString();

        if ($domainName === '') {
            $string->writeUInt8(0);
            return $string;
        }

        foreach (explode('.', $domainName) as $part) {
            // each label consists of a length octet followed by that number of octets.
            $string->writeUInt8(strlen($part));
            $string->append($part);
        }
        $string->writeUInt8(0); // The domain name terminates with the zero length octet for the null label of the root

        return $string;
    }

    public static function readDomainName(StringStream $stream): string
    {
        $labels = self::readLabel($stream);
        return implode('.', $labels);
    }

    private static function readLabel(StringStream $stream): array
    {
        $labels = [];
        do {
            $length = $stream->readUInt8();

            if ($length === 0) {
                break;
            }

            if (($length & 0b11000000) === 0b11000000) { // pointer TODO test combinations
                $offset = (0b00111111 & $length) << 8;
                $offset += $stream->readUInt8();

                $current = $stream->tell();
                $stream->seek($offset);

                $labels = array_merge($labels, self::readLabel($stream));

                $stream->seek($current);
                break;
            }

            // TODO handle reserved 10 and 01 starting bits ("The 10 and 01 combinations are reserved for future use")

            $labels[] = $stream->read($length);
        } while (true);

        return $labels;
    }

    public static function parseTimestamp(int $timestamp): DateTime
    {
        try {
            return new DateTime('@' . $timestamp);
        } catch (Exception) {
            throw new RuntimeException('Invalid timestamp: ' . $timestamp);
        }
    }

    public static function parseAtom(string $atom): DateTime
    {
        try {
            return new DateTime($atom);
        } catch (Exception) {
            throw new RuntimeException('Invalid datetime: ' . $atom);
        }
    }
}
