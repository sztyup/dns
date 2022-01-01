<?php

declare(strict_types=1);

namespace Sztyup\Dns\Meta\OptCodes;

class DHU extends RFC6975
{
    public const ALGORITHMS = [
        1 => 'SHA-1',
        2 => 'SHA-256',
        3 => 'GOST R 34.11-94',
        4 => 'SHA-384',
    ];
}
