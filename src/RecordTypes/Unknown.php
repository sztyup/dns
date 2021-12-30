<?php

declare(strict_types=1);

namespace Sztyup\Dns\RecordTypes;

use RuntimeException;
use Sztyup\Dns\Utilities\BinaryString;
use Sztyup\Dns\Utilities\StringStream;

use function strlen;

class Unknown extends ResourceRecord
{
    public string $data;

    protected function parseData(StringStream $stream, int $length): void
    {
        $this->data = $stream->read($length);
    }

    protected function wireData(): BinaryString
    {
        return new BinaryString($this->data);
    }

    protected function getTextRepresentation(): string
    {
        return '\\# ' . strlen($this->data) . ' ' . bin2hex($this->data);
    }

    public static function getId(): int
    {
        throw new RuntimeException('Undefined');
    }

    public static function getDescription(): string
    {
        return 'Catch all type of all unknown RR types';
    }
}
