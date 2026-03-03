<?php

/**
 * Tests for SodiumCipher.
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

use Horde\Secret\Cipher\SodiumCipher;
use Horde\Secret\Exception\EncryptionException;
use Horde\Secret\Exception\DecryptionException;
use Horde\Secret\Exception\InvalidKeyException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use PHPUnit\Framework\TestCase;

#[CoversClass(SodiumCipher::class)]
#[RequiresPhpExtension('sodium')]
class SodiumCipherTest extends TestCase
{
    private string $key;

    protected function setUp(): void
    {
        if (!SodiumCipher::isSupported()) {
            $this->markTestSkipped('Sodium extension not available');
        }

        $this->key = SodiumCipher::generateKey();
    }

    public function testIsSupportedReturnsTrue(): void
    {
        $this->assertTrue(SodiumCipher::isSupported());
    }

    public function testConstructorAcceptsValidKey(): void
    {
        $cipher = new SodiumCipher($this->key);

        $this->assertInstanceOf(SodiumCipher::class, $cipher);
        $this->assertEquals(0x02, $cipher->getVersion());
        $this->assertEquals('XSalsa20-Poly1305', $cipher->getName());
    }

    public function testConstructorRejectsShortKey(): void
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('must be exactly 32 bytes');

        new SodiumCipher('short-key');
    }

    public function testConstructorRejectsLongKey(): void
    {
        $this->expectException(InvalidKeyException::class);

        new SodiumCipher(str_repeat('x', 33));
    }

    public function testEncryptProducesCiphertext(): void
    {
        $cipher = new SodiumCipher($this->key);
        $plaintext = 'secret message';

        $ciphertext = $cipher->encrypt($plaintext);

        $this->assertNotEquals($plaintext, $ciphertext);
        $this->assertGreaterThan(strlen($plaintext), strlen($ciphertext));
    }

    public function testEncryptRejectsEmptyPlaintext(): void
    {
        $this->expectException(EncryptionException::class);
        $this->expectExceptionMessage('Cannot encrypt empty plaintext');

        $cipher = new SodiumCipher($this->key);
        $cipher->encrypt('');
    }

    public function testDecryptRestoresPlaintext(): void
    {
        $cipher = new SodiumCipher($this->key);
        $plaintext = 'secret message';

        $ciphertext = $cipher->encrypt($plaintext);
        $decrypted = $cipher->decrypt($ciphertext);

        $this->assertEquals($plaintext, $decrypted);
    }

    public function testDecryptWithWrongKeyFails(): void
    {
        $this->expectException(DecryptionException::class);
        $this->expectExceptionMessage('invalid ciphertext or wrong key');

        $cipher1 = new SodiumCipher($this->key);
        $ciphertext = $cipher1->encrypt('secret');

        $wrongKey = SodiumCipher::generateKey();
        $cipher2 = new SodiumCipher($wrongKey);
        $cipher2->decrypt($ciphertext);
    }

    public function testDecryptWithTamperedCiphertextFails(): void
    {
        $this->expectException(DecryptionException::class);

        $cipher = new SodiumCipher($this->key);
        $ciphertext = $cipher->encrypt('secret');

        // Tamper with ciphertext
        $tampered = $ciphertext;
        $tampered[strlen($tampered) - 1] = chr(ord($tampered[strlen($tampered) - 1]) ^ 0xFF);

        $cipher->decrypt($tampered);
    }

    public function testDecryptRejectsTooShortCiphertext(): void
    {
        $this->expectException(DecryptionException::class);
        $this->expectExceptionMessage('Ciphertext too short');

        $cipher = new SodiumCipher($this->key);
        $cipher->decrypt('short');
    }

    public function testEncryptProducesDifferentCiphertextEachTime(): void
    {
        $cipher = new SodiumCipher($this->key);
        $plaintext = 'same message';

        $ciphertext1 = $cipher->encrypt($plaintext);
        $ciphertext2 = $cipher->encrypt($plaintext);

        // Different nonces should produce different ciphertexts
        $this->assertNotEquals($ciphertext1, $ciphertext2);
    }

    public function testGetNonceLength(): void
    {
        $cipher = new SodiumCipher($this->key);

        $this->assertEquals(24, $cipher->getNonceLength());
        $this->assertEquals(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES, $cipher->getNonceLength());
    }

    public function testGetTagLength(): void
    {
        $cipher = new SodiumCipher($this->key);

        $this->assertEquals(16, $cipher->getTagLength());
        $this->assertEquals(SODIUM_CRYPTO_SECRETBOX_MACBYTES, $cipher->getTagLength());
    }

    public function testCiphertextLength(): void
    {
        $cipher = new SodiumCipher($this->key);
        $plaintext = 'test';

        $ciphertext = $cipher->encrypt($plaintext);

        // Ciphertext = nonce (24) + plaintext (4) + tag (16)
        $expectedLength = 24 + 4 + 16;
        $this->assertEquals($expectedLength, strlen($ciphertext));
    }

    public function testRoundTripWithBinaryData(): void
    {
        $cipher = new SodiumCipher($this->key);
        $binary = "\x00\x01\x02\xFF\xFE\xFD";

        $ciphertext = $cipher->encrypt($binary);
        $decrypted = $cipher->decrypt($ciphertext);

        $this->assertEquals($binary, $decrypted);
    }

    public function testRoundTripWithUnicode(): void
    {
        $cipher = new SodiumCipher($this->key);
        $unicode = '你好世界 🚀 Здравствуй мир';

        $ciphertext = $cipher->encrypt($unicode);
        $decrypted = $cipher->decrypt($ciphertext);

        $this->assertEquals($unicode, $decrypted);
    }

    public function testRoundTripWithLongMessage(): void
    {
        $cipher = new SodiumCipher($this->key);
        $long = str_repeat('Lorem ipsum dolor sit amet. ', 1000);

        $ciphertext = $cipher->encrypt($long);
        $decrypted = $cipher->decrypt($ciphertext);

        $this->assertEquals($long, $decrypted);
    }

    public function testGenerateKeyProducesValidKey(): void
    {
        $key = SodiumCipher::generateKey();

        $this->assertEquals(32, strlen($key));
        $this->assertEquals(SODIUM_CRYPTO_SECRETBOX_KEYBYTES, strlen($key));

        // Should be able to create cipher with generated key
        $cipher = new SodiumCipher($key);
        $this->assertInstanceOf(SodiumCipher::class, $cipher);
    }

    public function testGenerateKeyProducesDifferentKeys(): void
    {
        $key1 = SodiumCipher::generateKey();
        $key2 = SodiumCipher::generateKey();

        $this->assertNotEquals($key1, $key2);
    }

    public function testDifferentKeysProduceDifferentCiphertexts(): void
    {
        $plaintext = 'same message';

        $cipher1 = new SodiumCipher(SodiumCipher::generateKey());
        $ciphertext1 = $cipher1->encrypt($plaintext);

        $cipher2 = new SodiumCipher(SodiumCipher::generateKey());
        $ciphertext2 = $cipher2->encrypt($plaintext);

        $this->assertNotEquals($ciphertext1, $ciphertext2);
    }
}
