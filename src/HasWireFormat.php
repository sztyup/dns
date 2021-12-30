<?php

declare(strict_types=1);

namespace Sztyup\Dns;

use Sztyup\Dns\Utilities\BinaryString;
use Sztyup\Dns\Utilities\StringStream;

interface HasWireFormat
{
    public static function fromWireFormat(StringStream $stream, int $length): self;

    public function toWireFormat(): BinaryString;
}
