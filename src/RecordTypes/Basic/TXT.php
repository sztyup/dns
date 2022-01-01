<?php

declare(strict_types=1);

namespace Sztyup\Dns\RecordTypes\Basic;

use Sztyup\Dns\RecordTypes\ResourceRecord;
use Sztyup\Dns\Utilities\BinaryString;
use Sztyup\Dns\Utilities\StringStream;

use function strlen;

class TXT extends ResourceRecord
{
    public array $texts;

    protected function parseData(StringStream $stream, int $length): void
    {
        $start = $stream->tell();
        do {
            $stringLength  = $stream->readUInt8();
            $this->texts[] = $stream->read($stringLength);
        } while ($stream->tell() < $start + $length);
    }

    protected function wireData(): BinaryString
    {
        $data = new BinaryString();
        foreach ($this->texts as $text) {
            $data->writeUInt8(strlen($text));
            $data->append($text);
        }
        return $data;
    }

    public static function getId(): int
    {
        return 16;
    }

    protected function getTextRepresentation(): string
    {
        return '"' . implode('", "', $this->texts) . '"';
    }
}
