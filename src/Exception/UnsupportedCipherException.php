<?php

/**
 * Exception thrown when requested cipher is not supported.
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
 * Exception for unsupported cipher algorithms.
 *
 * Thrown when:
 * - Required PHP extension not available (e.g., sodium, openssl)
 * - Cipher version in ciphertext is unknown
 * - System doesn't support requested cipher
 *
 * @category  Horde
 * @copyright 2009-2026 Horde LLC
 * @license   http://www.horde.org/licenses/lgpl21 LGPL 2.1
 * @package   Secret
 */
class UnsupportedCipherException extends SecretException {}
