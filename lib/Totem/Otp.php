<?php

namespace Totem\Totem;

/**
 * @property false|string|null $secret
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
     * @param string|null $secret Clef privée, String en base64
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

        if ($this->last_time !== $time) {
            $hash = (string) hash_hmac('sha512', (string) $time, (string) $this->secret);

            //  Garde seulement les [key_size] bits les moins significatifs
            $hash = substr($hash, strlen($hash) - (self::$key_size / 4));

            $this->last_time = $time;
            $this->last_hash = $hash;
        } else {
            $hash = (string) $this->last_hash;
        }

        return base64_encode((string) hex2bin($hash));
    }
}
