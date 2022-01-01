<?php

declare(strict_types=1);

namespace Sztyup\Dns\Utilities;

use function ord;
use function strlen;

class Base32
{
    private const MAP_HEX = [
        '00000' => '0',
        '00001' => '1',
        '00010' => '2',
        '00011' => '3',
        '00100' => '4',
        '00101' => '5',
        '00110' => '6',
        '00111' => '7',
        '01000' => '8',
        '01001' => '9',
        '01010' => 'A',
        '01011' => 'B',
        '01100' => 'C',
        '01101' => 'D',
        '01110' => 'E',
        '01111' => 'F',
        '10000' => 'G',
        '10001' => 'H',
        '10010' => 'I',
        '10011' => 'J',
        '10100' => 'K',
        '10101' => 'L',
        '10110' => 'M',
        '10111' => 'N',
        '11000' => 'O',
        '11001' => 'P',
        '11010' => 'Q',
        '11011' => 'R',
        '11100' => 'S',
        '11101' => 'T',
        '11110' => 'U',
        '11111' => 'V',
    ];

    public static function encodeHex(string $string): string
    {
        $binary = '';

        $length = strlen($string);
        for ($i = 0; $i < $length; $i++) {
            $binary .= sprintf('%08b', ord($string[$i]));
        }

        $binary .= str_repeat('0', 5 - strlen($binary) % 5);

        $binary = str_split($binary, 5);

        $encoded = '';
        foreach ($binary as $bits) {
            $encoded .= self::MAP_HEX[$bits];
        }

        $encoded .= str_repeat('=', 8 - strlen($encoded) % 8);

        return $encoded;
    }
}
