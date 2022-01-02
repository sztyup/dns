<?php

declare(strict_types=1);

namespace Sztyup\Dns\Utilities;

use RuntimeException;

use function strlen;
use function substr;

class StringStream
{
    protected string $string;

    protected int $length;

    protected int $offset = 0;

    public function __construct(string $string)
    {
        $this->string = $string;
        $this->length = strlen($string);
    }

    public function readUInt8(): int
    {
        $unpacked = unpack('C', $this->read(1));

        if ($unpacked === false) {
            throw new RuntimeException('Cannot read UInt16');
        }

        return $unpacked[1];
    }

    public function readUInt16(): int
    {
        $unpacked = unpack('n', $this->read(2));

        if ($unpacked === false) {
            throw new RuntimeException('Cannot read UInt16');
        }

        return $unpacked[1];
    }

    public function readUInt32(): int
    {
        $unpacked = unpack('N', $this->read(4));

        if ($unpacked === false) {
            throw new RuntimeException('Cannot read UInt16');
        }

        return $unpacked[1];
    }

    public function readByteArray(int $length): array
    {
        $array = [];

        for ($i = 0; $i < $length; $i++) {
            $array[] = $this->readUInt8();
        }

        return $array;
    }

    public function read(int $length): string
    {
        if ($length < 0) {
            return substr($this->string, $this->offset -= $length, $length);
        }

        $result = substr($this->string, $this->offset, $length);

        $this->offset += $length;

        return $result;
    }

    public function peek(int $length): string
    {
        if ($length < 0) {
            return substr($this->string, $this->offset - $length, $length);
        }

        return substr($this->string, $this->offset, $length);
    }

    public function seek(int $offset): void
    {
        if ($offset < 0) {
            $this->offset = $this->length - $offset;
        } else {
            $this->offset = $offset;
        }

        if ($this->offset > $this->length) {
            throw new RuntimeException('Seek after EOF');
        }
    }

    public function tell(): int
    {
        return $this->offset;
    }

    public function eof(): bool
    {
        return $this->offset >= $this->length;
    }

    public function length(): int
    {
        return $this->length;
    }
}
