<?php

declare(strict_types=1);

namespace Sztyup\Dns\RecordTypes;

use RuntimeException;
use Sztyup\Dns\DnsConstants;
use Sztyup\Dns\DNSSEC\Algorithms\RSASHA1;
use Sztyup\Dns\DNSSEC\Algorithms\RSASHA256;
use Sztyup\Dns\Meta\OptCodes\DAU;
use Sztyup\Dns\Meta\OptCodes\OptCode;
use Sztyup\Dns\Utilities\BinaryString;
use Sztyup\Dns\Utilities\StringStream;

class OPT extends ResourceRecord
{
    public const MASK_RCODE   = 0b11111111000000000000000000000000;
    public const MASK_VERSION = 0b00000000111111110000000000000000;
    public const FLAG_DO      = 0b00000000000000001000000000000000;

    public int $payloadSize;

    public int $version;

    public bool $dnssec;

    public int $extendedErrorCode;

    /** @var OptCode[] */
    public array $options = [];

    public static function create(int $version, bool $do): OPT
    {
        $flags = $version << 16;

        if ($do) {
            $flags |= self::FLAG_DO;
        }

        $new = new self('', 4096, $flags);

        $new->options[] = new DAU([
            RSASHA1::getID(),
            RSASHA256::getID()
        ]);

        return $new;
    }

    protected function parseData(StringStream $stream, int $length): void
    {
        $this->payloadSize = $this->class;

        $flags = $this->ttl;

        $this->extendedErrorCode = ($flags & self::MASK_RCODE) >> 24;
        $this->version           = ($flags & self::MASK_VERSION) >> 16;
        $this->dnssec            = (bool)($flags & self::FLAG_DO);

        $start = $stream->tell();
        while ($stream->tell() < $start + $length) {
            $code      = $stream->readUInt16();
            $optLength = $stream->readUInt16();

            /** @var OptCode $opt */
            $opt = DnsConstants::OPT_CODES[$code];

            $this->options[$code] = $opt::fromWireFormat(new StringStream($stream->read($optLength)), $optLength);
        }
    }

    protected function wireData(): BinaryString
    {
        $data = new BinaryString();

        foreach ($this->options as $optionCode => $optionData) {
            $data->writeUInt16($optionCode);

            $wireData = $optionData->toWireFormat();
            $data->writeUInt16($wireData->length());
            $data->append($wireData);
        }

        return $data;
    }

    protected function getTextRepresentation(): string
    {
        throw new RuntimeException('No sense');
    }

    public function __toString(): string
    {
        throw new RuntimeException('No sense');
    }

    public static function getId(): int
    {
        return 41;
    }
}
