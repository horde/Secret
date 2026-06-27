<?php

/**
 * Tests for EncryptedData value object.
 *
 * Copyright 2009-2026 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 *
 * @category   Horde
 * @package    Secret
 * @subpackage UnitTests
 * @license    http://www.horde.org/licenses/lgpl21 LGPL 2.1
 */

declare(strict_types=1);

namespace Horde\Secret\Test\Unit;

use Horde\Secret\EncryptedData;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use InvalidArgumentException;

#[CoversClass(EncryptedData::class)]
class EncryptedDataTest extends TestCase
{
    public function testConstructorCreatesValidObject(): void
    {
        $version = 0x02;
        $payload = 'test-payload';

        $encrypted = new EncryptedData($version, $payload);

        $this->assertEquals($version, $encrypted->getVersion());
        $this->assertEquals($payload, $encrypted->getPayload());
    }

    public function testToStringIncludesMagicHeader(): void
    {
        $encrypted = new EncryptedData(0x02, 'payload');
        $data = $encrypted->toString();

        // Should start with 'HS' magic header
        $this->assertStringStartsWith('HS', $data);
        $this->assertEquals('H', $data[0]);
        $this->assertEquals('S', $data[1]);
        $this->assertEquals(chr(0x02), $data[2]);
    }

    public function testFromStringParsesCorrectly(): void
    {
        $original = new EncryptedData(0x03, 'test-data-123');
        $string = $original->toString();

        $parsed = EncryptedData::fromString($string);

        $this->assertEquals(0x03, $parsed->getVersion());
        $this->assertEquals('test-data-123', $parsed->getPayload());
        $this->assertEquals($string, $parsed->toString());
    }

    public function testFromStringRejectsInvalidFormat(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('missing magic header');

        EncryptedData::fromString('XX' . chr(0x02) . 'payload');
    }

    public function testFromStringRejectsTooShort(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('too short');

        EncryptedData::fromString('HS');
    }

    public function testConstructorRejectsInvalidVersion(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Version must be between');

        new EncryptedData(0x00, 'payload');
    }

    public function testConstructorRejectsVersionTooHigh(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new EncryptedData(0x100, 'payload');
    }

    public function testBase64Encoding(): void
    {
        $encrypted = new EncryptedData(0x02, 'test-payload');
        $base64 = $encrypted->toBase64();

        // Should be valid Base64
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9+\/]+=*$/', $base64);

        // Should decode back correctly
        $decoded = EncryptedData::fromBase64($base64);
        $this->assertEquals($encrypted->toString(), $decoded->toString());
    }

    public function testBase64UrlEncoding(): void
    {
        $encrypted = new EncryptedData(0x02, 'test-payload');
        $base64url = $encrypted->toBase64Url();

        // Should be URL-safe (no +, /, or =)
        $this->assertDoesNotMatchRegularExpression('/[+\/=]/', $base64url);
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]+$/', $base64url);

        // Should decode back correctly
        $decoded = EncryptedData::fromBase64Url($base64url);
        $this->assertEquals($encrypted->toString(), $decoded->toString());
    }

    public function testFromBase64RejectsInvalidBase64(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid Base64 encoding');

        EncryptedData::fromBase64('not valid base64!!!');
    }

    public function testHasHeaderDetectsMagicHeader(): void
    {
        $encrypted = new EncryptedData(0x02, 'payload');
        $data = $encrypted->toString();

        $this->assertTrue(EncryptedData::hasHeader($data));
    }

    public function testHasHeaderRejectsNonHeaderData(): void
    {
        $this->assertFalse(EncryptedData::hasHeader('AB' . chr(0x02) . 'data'));
        $this->assertFalse(EncryptedData::hasHeader('random data'));
        $this->assertFalse(EncryptedData::hasHeader('H'));  // Too short
        $this->assertFalse(EncryptedData::hasHeader(''));
    }

    public function testGetLength(): void
    {
        $payload = 'test-payload';
        $encrypted = new EncryptedData(0x02, $payload);

        // Length should be: 2 (magic) + 1 (version) + payload length
        $expectedLength = 2 + 1 + strlen($payload);
        $this->assertEquals($expectedLength, $encrypted->getLength());
    }

    public function testToStringMethodReturnsBase64(): void
    {
        $encrypted = new EncryptedData(0x02, 'payload');

        // __toString should return Base64
        $this->assertEquals($encrypted->toBase64(), (string) $encrypted);
    }

    public static function versionProvider(): array
    {
        return [
            'Version 0x01' => [0x01],
            'Version 0x02' => [0x02],
            'Version 0x03' => [0x03],
            'Version 0x0F' => [0x0F],
            'Version 0x7F' => [0x7F],
            'Version 0xFF' => [0xFF],
        ];
    }

    #[DataProvider('versionProvider')]
    public function testSupportsAllValidVersions(int $version): void
    {
        $encrypted = new EncryptedData($version, 'payload');

        $this->assertEquals($version, $encrypted->getVersion());
        $this->assertEquals(chr($version), $encrypted->toString()[2]);
    }

    public function testRoundTripWithBinaryPayload(): void
    {
        // Test with binary data including null bytes
        $binaryPayload = "\x00\x01\x02\xFF\xFE\xFD";
        $encrypted = new EncryptedData(0x02, $binaryPayload);

        // Round-trip through string
        $string = $encrypted->toString();
        $decoded = EncryptedData::fromString($string);

        $this->assertEquals($binaryPayload, $decoded->getPayload());
    }

    public function testRoundTripThroughBase64(): void
    {
        $encrypted = new EncryptedData(0x03, 'some data here');

        $base64 = $encrypted->toBase64();
        $decoded = EncryptedData::fromBase64($base64);

        $this->assertEquals($encrypted->getVersion(), $decoded->getVersion());
        $this->assertEquals($encrypted->getPayload(), $decoded->getPayload());
        $this->assertEquals($encrypted->toString(), $decoded->toString());
    }

    public function testRoundTripThroughBase64Url(): void
    {
        $encrypted = new EncryptedData(0x02, 'url safe data');

        $base64url = $encrypted->toBase64Url();
        $decoded = EncryptedData::fromBase64Url($base64url);

        $this->assertEquals($encrypted->getVersion(), $decoded->getVersion());
        $this->assertEquals($encrypted->getPayload(), $decoded->getPayload());
        $this->assertEquals($encrypted->toString(), $decoded->toString());
    }

    public function testEmptyPayloadAllowed(): void
    {
        // Empty payload should be allowed (cipher will reject empty plaintext)
        $encrypted = new EncryptedData(0x02, '');

        $this->assertEquals('', $encrypted->getPayload());
        $this->assertEquals(3, $encrypted->getLength()); // Just header
    }

    public function testLargePayload(): void
    {
        // Test with larger payload
        $largePayload = str_repeat('x', 10000);
        $encrypted = new EncryptedData(0x02, $largePayload);

        $this->assertEquals($largePayload, $encrypted->getPayload());
        $this->assertEquals(10003, $encrypted->getLength()); // header + payload
    }
}
