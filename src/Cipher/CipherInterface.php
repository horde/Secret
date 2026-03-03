<?php

/**
 * Interface for symmetric encryption ciphers.
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

/**
 * Interface for symmetric encryption ciphers.
 *
 * Implementations provide authenticated encryption using various algorithms
 * (XSalsa20-Poly1305, AES-256-GCM, etc.).
 *
 * @category  Horde
 * @copyright 2009-2026 Horde LLC
 * @license   http://www.horde.org/licenses/lgpl21 LGPL 2.1
 * @package   Secret
 */
interface CipherInterface
{
    /**
     * Get the cipher version identifier.
     *
     * Used in the format header to identify which cipher encrypted the data.
     *
     * @return int Version byte (0x01-0xFF)
     */
    public function getVersion(): int;

    /**
     * Get the cipher name.
     *
     * Human-readable name for logging and debugging.
     *
     * @return string Cipher name (e.g., 'XSalsa20-Poly1305', 'AES-256-GCM')
     */
    public function getName(): string;

    /**
     * Encrypt plaintext.
     *
     * @param string $plaintext Data to encrypt
     *
     * @return string Raw encrypted data (nonce + ciphertext + tag)
     *
     * @throws EncryptionException If encryption fails
     */
    public function encrypt(string $plaintext): string;

    /**
     * Decrypt ciphertext.
     *
     * @param string $ciphertext Raw encrypted data (nonce + ciphertext + tag)
     *
     * @return string Decrypted plaintext
     *
     * @throws DecryptionException If decryption fails or authentication fails
     */
    public function decrypt(string $ciphertext): string;

    /**
     * Check if this cipher is available on the system.
     *
     * @return bool True if cipher can be used
     */
    public static function isSupported(): bool;

    /**
     * Get the nonce length in bytes.
     *
     * @return int Nonce length (e.g., 24 for XSalsa20, 12 for AES-GCM)
     */
    public function getNonceLength(): int;

    /**
     * Get the authentication tag length in bytes.
     *
     * @return int Tag length (e.g., 16 for Poly1305, 16 for GCM)
     */
    public function getTagLength(): int;
}
