<?php

/**
 * Exception thrown when decryption fails.
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

namespace Horde\Secret\Exception;

/**
 * Exception for decryption failures.
 *
 * Thrown when:
 * - Ciphertext is corrupted or tampered with
 * - Authentication tag verification fails
 * - Wrong decryption key used
 * - Invalid ciphertext format
 *
 * @category  Horde
 * @copyright 2009-2026 Horde LLC
 * @license   http://www.horde.org/licenses/lgpl21 LGPL 2.1
 * @package   Secret
 */
class DecryptionException extends SecretException {}
