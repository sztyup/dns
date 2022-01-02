<?php

declare(strict_types=1);

namespace Sztyup\Dns\Meta\OptCodes;

use Sztyup\Dns\Utilities\BinaryString;
use Sztyup\Dns\Utilities\StringStream;

abstract class OptCode
{
    abstract public static function fromWireFormat(StringStream $stream, int $length): self;

    abstract public function toWireFormat(): BinaryString;
}
