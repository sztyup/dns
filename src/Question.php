<?php

declare(strict_types=1);

namespace Sztyup\Dns;

use Sztyup\Dns\Utilities\BinaryString;
use Sztyup\Dns\Utilities\DataFormats;
use Sztyup\Dns\Utilities\StringStream;

class Question
{
    public string $name;

    public int $type;

    public int $class;

    public function __construct(string $name, int $type, int $class)
    {
        $this->name  = $name;
        $this->type  = $type;
        $this->class = $class;
    }

    public static function fromWireFormat(StringStream $stream): Question
    {
        return new self(
            DataFormats::readDomainName($stream),
            $stream->readUInt16(),
            $stream->readUInt16()
        );
    }

    public function toWireFormat(): BinaryString
    {
        $query = new BinaryString();

        // QNAME
        $query->append(DataFormats::writeDomainName($this->name));

        // QTYPE
        $query->writeUInt16($this->type);

        // QCLASS
        $query->writeUInt16($this->class);

        return $query;
    }
}
