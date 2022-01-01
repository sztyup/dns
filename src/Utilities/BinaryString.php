<?php

declare(strict_types=1);

namespace Sztyup\Dns\Utilities;

use function strlen;

class BinaryString
{
    public function __construct(private string $string = '')
    {
    }

    public function writeUInt8(int $int): void
    {
        $this->string .= pack('C', $int);
    }

    public function writeUInt16(int $int): void
    {
        $this->string .= pack('n', $int);
    }

    public function writeUInt32(int $int): void
    {
        $this->string .= pack('N', $int);
    }

    public function writeBytes(array $bytes): void
    {
        foreach ($bytes as $byte) {
            $this->writeUInt8($byte);
        }
    }

    public function writeHexBytes(string $bytes): void
    {
        foreach (explode(' ', $bytes) as $byte) {
            $this->writeUInt8(hexdec($byte));
        }
    }

    public function append(BinaryString|string $string): void
    {
        $this->string .= $string;
    }

    public function __toString(): string
    {
        return $this->string;
    }

    public function toString(): string
    {
        return $this->string;
    }

    public function length(): int
    {
        return strlen($this->string);
    }
}
