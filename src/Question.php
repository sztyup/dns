<?php

declare(strict_types=1);

namespace Sztyup\Dns;

use Sztyup\Dns\Utilities\BinaryString;
use Sztyup\Dns\Utilities\DataFormats;
use Sztyup\Dns\Utilities\StringStream;

class Question implements HasWireFormat
{
    public string $name;

    public int $type;

    public int $class;

    public static function createFrom(string $name, int $type, int $class): Question
    {
        $new = new self();

        $new->name  = $name;
        $new->type  = $type;
        $new->class = $class;

        return $new;
    }

    public static function fromWireFormat(StringStream $stream, int $length): Question
    {
        $new = new self();

        $new->name  = DataFormats::readDomainName($stream);
        $new->type  = $stream->readUInt16();
        $new->class = $stream->readUInt16();

        return $new;
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
