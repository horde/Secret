<?php

/**
 * Tests for BlowfishCipher legacy adapter.
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

namespace Horde\Secret\Test\Unit\Cipher;

use Horde\Secret\Cipher\BlowfishCipher;
use Horde\Secret\Exception\InvalidKeyException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(BlowfishCipher::class)]
class BlowfishCipherTest extends TestCase
{
    protected function setUp(): void
    {
        if (!BlowfishCipher::isSupported()) {
            $this->markTestSkipped('Blowfish cipher not available');
        }
    }

    public function testIsSupportedReturnsTrue(): void
    {
        $this->assertTrue(BlowfishCipher::isSupported());
    }

    public function testConstructorAcceptsValidKey(): void
    {
        $cipher = new BlowfishCipher('test-key-12345');

        $this->assertInstanceOf(BlowfishCipher::class, $cipher);
        $this->assertEquals(0x01, $cipher->getVersion());
        $this->assertEquals('Blowfish-ECB', $cipher->getName());
    }

    public function testConstructorRejectsEmptyKey(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('cannot be empty');

        new BlowfishCipher('');
    }

    public function testEncryptAndDecryptRoundTrip(): void
    {
        $cipher = new BlowfishCipher('secret-key');
        $plaintext = 'secret message';

        $ciphertext = $cipher->encrypt($plaintext);
        $decrypted = $cipher->decrypt($ciphertext);

        $this->assertEquals($plaintext, $decrypted);
    }

    public function testEncryptEmptyStringReturnsEmpty(): void
    {
        $cipher = new BlowfishCipher('key');

        // Matches PSR-0 behavior: empty input = empty output
        $result = $cipher->encrypt('');

        $this->assertEquals('', $result);
    }

    public function testDecryptEmptyStringReturnsEmpty(): void
    {
        $cipher = new BlowfishCipher('key');

        // Matches PSR-0 behavior
        $result = $cipher->decrypt('');

        $this->assertEquals('', $result);
    }

    public function testKeyTruncation(): void
    {
        // Blowfish keys are truncated to 56 bytes
        $longKey = str_repeat('x', 100);

        $cipher = new BlowfishCipher($longKey);

        // Should succeed (key truncated internally)
        $ciphertext = $cipher->encrypt('test');
        $decrypted = $cipher->decrypt($ciphertext);

        $this->assertEquals('test', $decrypted);
    }

    public function testDifferentKeysSameData(): void
    {
        $plaintext = 'test data';

        $cipher1 = new BlowfishCipher('key1');
        $ciphertext1 = $cipher1->encrypt($plaintext);

        $cipher2 = new BlowfishCipher('key2');
        $ciphertext2 = $cipher2->encrypt($plaintext);

        // Same data with different keys produces different ciphertext
        $this->assertNotEquals($ciphertext1, $ciphertext2);
    }

    public function testGetNonceLengthReturnsZero(): void
    {
        $cipher = new BlowfishCipher('key');

        // Blowfish ECB doesn't use nonces
        $this->assertEquals(0, $cipher->getNonceLength());
    }

    public function testGetTagLengthReturnsZero(): void
    {
        $cipher = new BlowfishCipher('key');

        // Blowfish doesn't have authentication tags
        $this->assertEquals(0, $cipher->getTagLength());
    }

    public function testRoundTripWithBinaryData(): void
    {
        $cipher = new BlowfishCipher('binary-key');
        $binary = "\x00\x01\x02\xFF\xFE\xFD";

        $ciphertext = $cipher->encrypt($binary);
        $decrypted = $cipher->decrypt($ciphertext);

        $this->assertEquals($binary, $decrypted);
    }

    public function testCompatibilityWithHordeSecret(): void
    {
        // Test compatibility with PSR-0 Horde_Secret
        $key = 'test-key-12345';
        $plaintext = "\x01\x01\x01\x01\x01\x01\x01\x01";

        $cipher = new BlowfishCipher($key);
        $encrypted = $cipher->encrypt($plaintext);
        $decrypted = $cipher->decrypt($encrypted);

        $this->assertEquals($plaintext, $decrypted);
    }
}
