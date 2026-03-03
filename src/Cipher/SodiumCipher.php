<?php

/**
 * XSalsa20-Poly1305 authenticated encryption using libsodium.
 *
 * Copyright 2009-2026 Horde LLC (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (LGPL). If you
 * did not receive this file, see http://www.horde.org/licenses/lgpl21.
 *
 * @category  Horde
 * @copyright 2009-2026 Horde LLC
 * @license   http://www.horde.org/licenses/lgpl21 LGPL 2.1
 * @package   Secret
 */

declare(strict_types=1);

namespace Horde\Secret\Cipher;

use Horde\Secret\Exception\EncryptionException;
use Horde\Secret\Exception\DecryptionException;
use Horde\Secret\Exception\InvalidKeyException;

/**
 * Sodium cipher using XSalsa20-Poly1305 authenticated encryption.
 *
 * This is the recommended modern cipher for new deployments.
 *
 * Features:
 * - XSalsa20 stream cipher (fast, secure)
 * - Poly1305 authentication (prevents tampering)
 * - 256-bit keys
 * - 192-bit nonces (safe for random generation)
 * - Constant-time operations
 *
 * @category  Horde
 * @copyright 2009-2026 Horde LLC
 * @license   http://www.horde.org/licenses/lgpl21 LGPL 2.1
 * @package   Secret
 */
final class SodiumCipher implements CipherInterface
{
    /**
     * Cipher version identifier.
     */
    private const VERSION = 0x02;

    /**
     * Cipher name.
     */
    private const NAME = 'XSalsa20-Poly1305';

    /**
     * Encryption key.
     *
     * @var string 32-byte (256-bit) key
     */
    private readonly string $key;

    /**
     * Constructor.
     *
     * @param string $key Encryption key (must be 32 bytes for XSalsa20)
     *
     * @throws InvalidKeyException If key length is invalid
     */
    public function __construct(string $key)
    {
        if (strlen($key) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            throw new InvalidKeyException(sprintf(
                'Key must be exactly %d bytes, got %d bytes',
                SODIUM_CRYPTO_SECRETBOX_KEYBYTES,
                strlen($key)
            ));
        }

        $this->key = $key;
    }

    /**
     * {@inheritdoc}
     */
    public function getVersion(): int
    {
        return self::VERSION;
    }

    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return self::NAME;
    }

    /**
     * {@inheritdoc}
     */
    public function encrypt(string $plaintext): string
    {
        if ($plaintext === '') {
            throw new EncryptionException('Cannot encrypt empty plaintext');
        }

        try {
            // Generate random nonce (24 bytes)
            $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

            // Encrypt with authentication
            $ciphertext = sodium_crypto_secretbox($plaintext, $nonce, $this->key);

            // Return: nonce + ciphertext (which includes auth tag)
            return $nonce . $ciphertext;
        } catch (\Exception $e) {
            throw new EncryptionException(
                'Encryption failed: ' . $e->getMessage(),
                0,
                $e
            );
        }
    }

    /**
     * {@inheritdoc}
     */
    public function decrypt(string $ciphertext): string
    {
        $minLength = SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES;

        if (strlen($ciphertext) < $minLength) {
            throw new DecryptionException(sprintf(
                'Ciphertext too short (minimum %d bytes)',
                $minLength
            ));
        }

        try {
            // Extract nonce (first 24 bytes)
            $nonce = substr($ciphertext, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

            // Extract encrypted data (rest)
            $encrypted = substr($ciphertext, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

            // Decrypt and verify authentication
            $plaintext = sodium_crypto_secretbox_open($encrypted, $nonce, $this->key);

            if ($plaintext === false) {
                throw new DecryptionException(
                    'Decryption failed: invalid ciphertext or wrong key'
                );
            }

            return $plaintext;
        } catch (DecryptionException $e) {
            throw $e;
        } catch (\Exception $e) {
            throw new DecryptionException(
                'Decryption failed: ' . $e->getMessage(),
                0,
                $e
            );
        }
    }

    /**
     * {@inheritdoc}
     */
    public static function isSupported(): bool
    {
        return extension_loaded('sodium');
    }

    /**
     * {@inheritdoc}
     */
    public function getNonceLength(): int
    {
        return SODIUM_CRYPTO_SECRETBOX_NONCEBYTES; // 24 bytes
    }

    /**
     * {@inheritdoc}
     */
    public function getTagLength(): int
    {
        return SODIUM_CRYPTO_SECRETBOX_MACBYTES; // 16 bytes
    }

    /**
     * Generate a random encryption key.
     *
     * @return string 32-byte random key
     */
    public static function generateKey(): string
    {
        return random_bytes(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
    }

    /**
     * Securely zero the key in memory (when object is destroyed).
     */
    public function __destruct()
    {
        try {
            sodium_memzero($this->key);
        } catch (\Error) {
            // Key is readonly, can't be zeroed
            // This is acceptable - PHP will clean up memory
        }
    }
}
