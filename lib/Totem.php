<?php

namespace Totem;

class Totem {
    const ERR_NO_NAMESPACE = 32;

    /**
     * Instance du singleton Totem.
     *
     * @var self|null
     */
    private static $instance = null;

    /**
     * Lecture de l'instance de Totem
     *
     * @return self
     */
    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    /**
     * Version de l'API à utiliser sur le serveur
     * ~2 = 2.*.*
     *
     * @var string
     */
    private static $api_version = '~2';

    /**
     * URL de base de Totem.
     * Ex: http://totem.gammadia.ch/
     *
     * @var string|null
     */
    private static $totem_base_url = null;

    /**
     * Défini l'URL de Totem.
     *
     * @param string $url
     * @see self::$totem_base_url
     *
     * @return void
     */
    public static function setUrl($url = '') {
        if (strrchr($url, '/') !== '/') {
            $url .= '/';
        }

        self::$totem_base_url = $url;
    }

    /**
     * Nom de l'application.
     *
     * @var string|null
     */
    private static $app_name = null;

    /**
     * Défini le nom de l'application.
     *
     * @param string $name
     * @see self::$app_name
     *
     * @return void
     */
    public static function setApplicationName($name = '') {
        self::$app_name = $name;
    }

    /**
     * Clef de l'application.
     *
     * @var string|null
     */
    private static $app_key = null;

    /**
     * Défini la clef de l'application.
     *
     * @param string $key
     * @see self::$app_key
     *
     * @return void
     */
    public static function setApplicationKey($key = '') {
        self::$app_key = $key;
    }

    /**
     * Cache des données utilisateur
     *
     * @var array<string, mixed[]>
     */
    private static $cache = array();

    /**
     * Constructeur privé. (Singleton)
     */
    private function __construct() {}

    /**
     * Générateur Otp
     *
     * @var \Totem\Totem\Otp|null
     */
    private $generator = null;

    /**
     * Requête sur la base Totem
     *
     * @param string $resource Resource (url)
     * @param string $type GET || POST
     * @param mixed[] $data Données pour les requêtes POST
     *
     * @return mixed Données reçues
     */
    public function makeRequest($resource, $type = 'GET', $data = array()) {
        if (null === self::$totem_base_url) {
            throw new \UnexpectedValueException(sprintf('You must call %s::setUrl() before using Totem.', self::class));
        }

        $ch = curl_init(self::$totem_base_url . $resource);

        if (!$ch) {
            throw new \UnexpectedValueException('Unable to init cURL handler.');
        }

        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array(
            $this->getAuthHeader(),
            'Accept-Version: ' . self::$api_version
        ));

        if (strtoupper($type) === 'POST') {
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
        }

        if (strtoupper($type) === 'PUT') {
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PUT');
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
        }

        $data = curl_exec($ch);

        curl_close($ch);

        return $data;
    }

    /**
     * Création du token http authentication pour Totem
     * TIPI-TOKEN appid="xxx", sign="xxx"
     *
     * @return string
     */
    private function getToken() {
        if (!$this->generator) {
            $this->generator = new Totem\Otp(self::$app_key);
        }

        $sign = hash_hmac('sha256', (string) self::$app_key, $this->generator->getCode());
        $sign = base64_encode((string) hex2bin($sign));

        $token = 'TIPI-TOKEN ' .
                'app="' . self::$app_name . '", ' .
                'sign="' . $sign . '"';

        return $token;
    }

    /**
     * Création du header d'authentification
     *
     * @return string
     */
    public function getAuthHeader() {
        return 'Authorization: ' . $this->getToken();
    }

    /**
     * Lecture des données de l'utilisateur actuel pour le namespace donné.
     *
     * @param string $namespace
     * @param boolean $force_refresh Forcer le rechargement des données, ne pas lire le cache.
     *
     * @return array{success: bool, reason?: string, data?: mixed[]}
     */
    public function getUserData($namespace, $force_refresh = false) {
        if (empty($namespace)) {
            return array(
                'success' => false,
                'reason' => 'No namespace given'
            );
        }

        $session = Totem\Session::getInstance();

        if (!$session->isValid()) {
            return array(
                'success' => false,
                'reason' => 'Invalid session'
            );
        }

        if ($force_refresh || !isset(self::$cache[$namespace])) {
            self::$cache[$namespace] = json_decode(
                $this->makeRequest('session/' . $session->getId() . '/' . $namespace),
                true
            );
        }

        return array(
            'success' => true,
            'data' => self::$cache[$namespace]
        );
    }

    /**
     * Écriture des données de l'utilisateur actuel dans le namespace donné
     *
     * /!\ Attention /!\
     * Écrase les données.
     * Faire un getUserData('xxx', true) avant, modifier les données, et setUserData().
     * Le $force_refresh de getUserData() est aussi fortement conseillé, pour éviter les données non à jour.
     *
     * setUserData('xxx', array(), string), va vider le namespace 'xxx'.
     *
     * @param string $namespace
     * @param mixed[] $data Données, le contenu du namespace complet sera remplacé.
     * @param string $totemId Totem id of the user
     *
     * @return array{success: bool, reason?: string, data?: mixed[]}
     */
    public function setUserData($namespace, $data, $totemId = null) {
        $session = Totem\Session::getInstance();

        if (!$session->isValid()) {
            return array(
                'success' => false,
                'reason' => 'Invalid session'
            );
        }

        $path = isset($totemId) ? 'session/' . $totemId . '/' . $namespace : 'session/' . $session->getId() . '/' . $namespace;

        $result = $this->makeRequest($path,
            'PUT',
            $data
        );

        if ($result === false) {
            return array(
                'success' => false
            );
        } else {
            self::$cache[$namespace] = json_decode($result, true);

            return array(
                'success' => true,
                'data' => self::$cache[$namespace]
            );
        }

    }
}
