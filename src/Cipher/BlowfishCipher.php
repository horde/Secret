<?php

/**
 * Blowfish cipher adapter for legacy compatibility.
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

use Horde_Crypt_Blowfish;
use Horde\Secret\Exception\EncryptionException;
use Horde\Secret\Exception\DecryptionException;
use Horde\Secret\Exception\InvalidKeyException;

/**
 * Blowfish cipher adapter wrapping Horde_Crypt_Blowfish.
 *
 * LEGACY CIPHER - For backward compatibility only.
 * Do NOT use for new data - use SodiumCipher or AesGcmCipher instead.
 *
 * Limitations:
 * - No authenticated encryption (vulnerable to tampering)
 * - 56-byte key limit
 * - ECB mode (no IV)
 * - Legacy algorithm (1993)
 *
 * @category  Horde
 * @copyright 2009-2026 Horde LLC
 * @license   http://www.horde.org/licenses/lgpl21 LGPL 2.1
 * @package   Secret
 */
final class BlowfishCipher implements CipherInterface
{
    /**
     * Cipher version identifier.
     *
     * Note: Version 0x01 is reserved for future Blowfish WITH header.
     * Legacy data has no header, so we don't use a version for it.
     */
    private const VERSION = 0x01;

    /**
     * Cipher name.
     */
    private const NAME = 'Blowfish-ECB';

    /**
     * Maximum key length (Blowfish limitation).
     */
    private const MAX_KEY_LENGTH = 56;

    /**
     * Blowfish cipher instance.
     *
     * @var Horde_Crypt_Blowfish
     */
    private readonly Horde_Crypt_Blowfish $cipher;

    /**
     * Original key for re-creating cipher if needed.
     *
     * @var string
     */
    private readonly string $key;

    /**
     * Constructor.
     *
     * @param string $key Encryption key (up to 56 bytes, will be truncated)
     *
     * @throws InvalidKeyException If key is empty
     */
    public function __construct(string $key)
    {
        if ($key === '') {
            throw new InvalidKeyException('Key cannot be empty');
        }

        // Truncate key to maximum length (Blowfish limitation)
        $this->key = substr($key, 0, self::MAX_KEY_LENGTH);

        try {
            $this->cipher = new Horde_Crypt_Blowfish($this->key);
        } catch (\Exception $e) {
            throw new InvalidKeyException(
                'Failed to initialize Blowfish cipher: ' . $e->getMessage(),
                0,
                $e
            );
        }
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
            // Match PSR-0 behavior: return empty string
            return '';
        }

        try {
            return $this->cipher->encrypt($plaintext);
        } catch (\Exception $e) {
            throw new EncryptionException(
                'Blowfish encryption failed: ' . $e->getMessage(),
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
        if ($ciphertext === '') {
            // Match PSR-0 behavior: return empty string
            return '';
        }

        try {
            return $this->cipher->decrypt($ciphertext);
        } catch (\Exception $e) {
            throw new DecryptionException(
                'Blowfish decryption failed: ' . $e->getMessage(),
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
        return class_exists('Horde_Crypt_Blowfish');
    }

    /**
     * {@inheritdoc}
     */
    public function getNonceLength(): int
    {
        // Blowfish ECB mode doesn't use nonces
        return 0;
    }

    /**
     * {@inheritdoc}
     */
    public function getTagLength(): int
    {
        // Blowfish doesn't have authentication tags
        return 0;
    }
}
