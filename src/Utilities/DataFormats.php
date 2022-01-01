<?php

declare(strict_types=1);

namespace Sztyup\Dns\Utilities;

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

    public static function writeDomainName(string $domainName): string
    {
        if ($domainName === '') {
            return pack('C', 0);
        }

        $string = '';
        foreach (explode('.', $domainName) as $part) {
            // each label consists of a length octet followed by that number of octets.
            $string .= pack('C', strlen($part)) . $part;
        }
        $string .= pack('C', 0); // The domain name terminates with the zero length octet for the null label of the root

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
            $length = unpack('C', $stream->read(1));

            if ($length === false) {
                throw new RuntimeException('Invalid label');
            }

            if ($length[1] === 0) {
                break;
            }

            if ($length[1] & 0b11000000) { // pointer TODO test combinations
                $offset = (0b00111111 & $length[1]) << 8;
                $offset += $stream->readUInt8();

                $current = $stream->tell();
                $stream->seek($offset);

                $labels = array_merge($labels, self::readLabel($stream));

                $stream->seek($current);
                break;
            }

            // TODO handle reserved 10 and 01 starting bits ("The 10 and 01 combinations are reserved for future use")

            $labels[] = $stream->read($length[1]);
        } while (true);

        return $labels;
    }
}
