<?php

declare(strict_types=1);

namespace Sztyup\Dns;

use IPLib\Address\AddressInterface;
use IPLib\Address\IPv4;
use RuntimeException;
use Socket\Raw\Factory;
use Sztyup\Dns\Utilities\StringStream;

use function strlen;

class Client
{
    protected Factory $socketFactory;

    protected QueryBuilder $queryBuilder;

    protected AddressInterface $server;

    protected int $serverPort;

    public function __construct(string $server = '8.8.8.8')
    {
        $this->socketFactory = new Factory();
        $this->queryBuilder  = new QueryBuilder();
        $this->server        = IPv4::parseString($server);
        $this->serverPort    = 53;
    }

    public function by(string $server): static
    {
        $this->server = IPv4::parseString($server);

        return $this;
    }

    public function query(string $domain, int $typeId): Message
    {
        $request = $this->queryBuilder->build($domain, $typeId);

        $response = $this->sendByTCP($request->toWireFormat()->toString());

        $message = Message::fromWireFormat($response, $response->length());

        if ($message->hasError()) {
            throw new RuntimeException('DNS ERROR: ' . DnsConstants::ERROR_TYPES[$message->errorCode][0]);
        }

        return $message;
    }

    protected function sendByUDP(string $data): StringStream
    {
        if (strlen($data) > 512) {
            throw new RuntimeException('Specification does not allow UDP messages above 512 bytes');
        }

        $socket = $this->socketFactory->createClient('udp://' . $this->server->toString() . ':' . $this->serverPort);
        $socket->write($data);

        return new StringStream($socket->read(4096));
    }

    protected function sendByTCP(string $data): StringStream
    {
        $socket = $this->socketFactory->createClient('tcp://' . $this->server->toString() . ':' . $this->serverPort);
        $socket->write(pack('n', strlen($data)) . $data);

        $length = unpack('n', $socket->read(2));
        if ($length === false) {
            throw new RuntimeException('Error in response length');
        }

        return new StringStream($socket->read($length[1]));
    }
}
