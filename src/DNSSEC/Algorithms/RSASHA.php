<?php

declare(strict_types=1);

namespace Sztyup\Dns\DNSSEC\Algorithms;

use phpseclib3\Crypt\Common\PublicKey;
use phpseclib3\Crypt\RSA;
use phpseclib3\Math\BigInteger;
use RuntimeException;
use Sztyup\Dns\Utilities\StringStream;

abstract class RSASHA implements Algorithm
{
    public BigInteger $exponent;

    public BigInteger $modulus;

    public function __construct(StringStream $stream, int $length)
    {
        $start = $stream->tell();

        $exponentLength = $stream->readUInt8();
        if ($exponentLength === 0) {
            $exponentLength = $stream->readUInt16();
        }

        $this->exponent = new BigInteger($stream->read($exponentLength), 256);
        $this->modulus  = new BigInteger($stream->read($length - $stream->tell() - $start), 256);
    }

    public function toPublicKey(): PublicKey
    {
        $key = RSA::loadParameters([
            'modulus'  => $this->modulus,
            'exponent' => $this->exponent,
        ]);

        if (!$key instanceof RSA || !$key instanceof PublicKey) {
            throw new RuntimeException('Cannot create RSA key');
        }

        return $key->withHash($this->getHash())
            ->withPadding(RSA::SIGNATURE_PKCS1);
    }

    abstract protected function getHash(): string;
}
