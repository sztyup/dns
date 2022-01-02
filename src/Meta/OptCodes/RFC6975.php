<?php

declare(strict_types=1);

namespace Sztyup\Dns\Meta\OptCodes;

use RuntimeException;
use Sztyup\Dns\Utilities\BinaryString;
use Sztyup\Dns\Utilities\StringStream;

abstract class RFC6975 extends OptCode
{
    public const ALGORITHMS = [];

    public array $supportedAlgorithms;

    public static function create(array $algorithms): static
    {
        $new = new static();

        $new->supportedAlgorithms = $algorithms;

        return $new;
    }

    public static function fromWireFormat(StringStream $stream, int $length): static
    {
        $new = new static();

        for ($i = 0; $i < $length; $i++) {
            $code = $stream->readUInt8();

            if (!isset(static::ALGORITHMS[$code])) {
                throw new RuntimeException('Unsupported algorithm code');
            }

            $new->supportedAlgorithms[] = $code;
        }

        return $new;
    }

    public function toWireFormat(): BinaryString
    {
        $data = new BinaryString();

        foreach ($this->supportedAlgorithms as $code) {
            if (!isset(static::ALGORITHMS[$code])) {
                throw new RuntimeException('Unsupported algorithm code');
            }

            $data->writeUInt8($code);
        }

        return $data;
    }
}
