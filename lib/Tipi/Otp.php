<?php

namespace Tipi\Tipi;

/**
 * @property false|string $secret
 */
class Otp {
	/**
	 * Taille, en bit, du passe à générer.
	 *
	 * @var int
	 */
	private static $key_size = 96;

	/**
	 * Base du dernier hash généré.
	 *
	 * @var float|null
	 */
	private $last_time = null;

	/**
	 * Dernier code retourné.
	 *
	 * @var string|null
	 */
	private $last_hash = null;

	/**
	 * Création d'un générateur OTP
	 *
	 * @param string $secret Clef privée, String en base64
	 */
	public function __construct($secret) {
		if (is_string($secret)) {
			$secret = base64_decode($secret);
		}

		$this->secret = $secret;
	}

	/**
	 * Création du code et encodage en base64
	 *
	 * @return string Code en base64
	 */
	public function getCode() {
		$time = floor(time() / 30);   //  Unix timestamp / 30
		$hash = null;

		if ($this->last_time !== $time) {
			$hash = hash_hmac('sha512', $time, $this->secret);

			//  Garde seulement les [key_size] bits les moins significatifs
			$hash = substr($hash, strlen($hash) - (self::$key_size / 4));

			$this->last_time = $time;
			$this->last_hash = $hash;
		} else {
			$hash = $this->last_hash;
		}

		return base64_encode(hex2bin($hash));
	}
}
