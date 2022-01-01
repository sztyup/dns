<?php

declare(strict_types=1);

namespace Sztyup\Dns\RecordTypes;

use RuntimeException;
use Sztyup\Dns\DnsConstants;
use Sztyup\Dns\Utilities\BinaryString;
use Sztyup\Dns\Utilities\StringStream;

use function strlen;

class Unknown extends ResourceRecord
{
    public int $id;

    public string $data;

    public function __construct(string $name, int $class, int $ttl, int $id)
    {
        parent::__construct($name, $class, $ttl);

        $this->id = $id;
    }

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

    public function __toString(): string
    {
        $class = DnsConstants::CLASSES[$this->class] ?? null;

        if ($class === null) {
            $class = 'CLASS' . $this->class;
        }

        return sprintf(
            '%s. %s %s %s',
            $this->name,
            $class,
            'TYPE' . $this->id,
            $this->getTextRepresentation()
        );
    }

    public function getActualId(): int
    {
        return $this->id;
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
