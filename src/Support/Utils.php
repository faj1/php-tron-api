<?php
namespace IEXBase\TronAPI\Support;

use Exception;
use InvalidArgumentException;

class Utils
{
    /**
     * Link verification
     *
     * @param $url
     * @return bool
     */
    public static function isValidUrl($url) :bool {
        return (bool)parse_url($url);
    }

    /**
     * Check whether the passed parameter is an array
     *
     * @param $array
     * @return bool
     */
    public static function isArray($array) : bool {
        return is_array($array);
    }

    /**
     * isZeroPrefixed
     *
     * @param string
     * @return bool
     */
    public static function isZeroPrefixed($value)
    {
        if (!is_string($value)) {
            throw new InvalidArgumentException('The value to isZeroPrefixed function must be string.');
        }
        return (strpos($value, '0x') === 0);
    }

    /**
     * stripZero
     *
     * @param string $value
     * @return string
     */
    public static function stripZero($value)
    {
        if (self::isZeroPrefixed($value)) {
            $count = 1;
            return str_replace('0x', '', $value, $count);
        }
        return $value;
    }

    /**
     * isNegative
     *
     * @param string
     * @return bool
     */
    public static function isNegative($value)
    {
        if (!is_string($value)) {
            throw new InvalidArgumentException('The value to isNegative function must be string.');
        }
        return (strpos($value, '-') === 0);
    }

    /**
     * Check if the string is a 16th notation
     *
     * @param $str
     * @return bool
     */
    public static function isHex($str) : bool {
        return is_string($str) and ctype_xdigit($str);
    }

    /**
     * hexToBin
     *
     * @param string
     * @return string
     */
    public static function hexToBin($value)
    {
        if (!is_string($value)) {
            throw new InvalidArgumentException('The value to hexToBin function must be string.');
        }
        if (self::isZeroPrefixed($value)) {
            $count = 1;
            $value = str_replace('0x', '', $value, $count);
        }
        return pack('H*', $value);
    }

    /**
     * @param $address
     * @return bool
     * @throws Exception
     */
    public static function validate($address)
    {
        $decoded = Base58::decode($address);

        $d1 = hash("sha256", substr($decoded,0,21), true);
        $d2 = hash("sha256", $d1, true);

        if(substr_compare($decoded, $d2, 21, 4)){
            throw new \Exception("bad digest");
        }
        return true;
    }

    /**
     * @throws Exception
     */
    public static function decodeBase58($input)
    {
        $alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

        $out = array_fill(0, 25, 0);
        for($i=0;$i<strlen($input);$i++){
            if(($p=strpos($alphabet, $input[$i]))===false){
                throw new Exception("invalid character found");
            }
            $c = $p;
            for ($j = 25; $j--; ) {
                $c += (int)(58 * $out[$j]);
                $out[$j] = (int)($c % 256);
                $c /= 256;
                $c = (int)$c;
            }
            if($c != 0){
                throw new Exception("address too long");
            }
        }

        $result = "";
        foreach($out as $val){
            $result .= chr($val);
        }

        return $result;
    }

    /**
     *
     * @throws Exception
     */
    public static function pubKeyToAddress($pubkey) {
        return '41'. substr(Keccak::hash(substr(hex2bin($pubkey), 1), 256), 24);
    }

    /**
     * Test if a string is prefixed with "0x".
     *
     * @param string $str
     *   String to test prefix.
     *
     * @return bool
     *   TRUE if string has "0x" prefix or FALSE.
     */
    public static function hasHexPrefix($str)
    {
        return substr($str, 0, 2) === '0x';
    }

    /**
     * Remove Hex Prefix "0x".
     *
     * @param string $str
     * @return string
     */
    public static function removeHexPrefix($str)
    {
        if (!self::hasHexPrefix($str)) {
            return $str;
        }
        return substr($str, 2);
    }


    /**
     * 将T开头的地址转换为 41 开头的地址
     *
     * @param string $base58Address T开头的TRON地址
     * @return string 返回41开头的十六进制地址
     * @throws Exception 如果地址无效会抛出异常
     */
    public static function Tto41(string $base58Address): string
    {
        // 检查地址是否 T 开头
        if ($base58Address[0] !== 'T') {
            throw new Exception('TRON地址必须以T开头');
        }
        // Base58 解码
        $decoded = self::base58_decode($base58Address);
        // 移除前1字节版本和后4字节校验和，获取HEX地址内容
        $hexAddress = bin2hex(substr($decoded, 0, -4)); // 拿掉末尾4字节校验和
        // 确保版本号为常见的 TRON 地址版本号41（也可以自定义其他处理）
        if (!str_starts_with($hexAddress, '41')) {
            throw new Exception('地址解析失败，非41开头');
        }
        return $hexAddress; // 返回41开头的十六进制地址
    }

    /**
     * 将 41 开头的十六进制地址转换为 T 开头的地址
     * @param string $hexAddress 41开头的HEX地址
     * @return string 返回Base58编码的T开头地址
     * @throws Exception 如果地址无效会抛出异常
     */
    public static function hexToT(string $hexAddress): string
    {
        // 检查HEX地址是否合法
        if (!str_starts_with($hexAddress, '41') || strlen($hexAddress) !== 42) {
            throw new Exception('HEX地址必须是41开头，长度为42的字符串');
        }
        // 转换HEX地址为二进制
        $payload = hex2bin($hexAddress);
        if ($payload === false) {
            throw new Exception('无效的HEX地址');
        }
        // 计算校验和
        $checksum = substr(hash('sha256', hash('sha256', $payload, true), true), 0, 4);
        // 拼接数据后进行Base58编码
        return self::base58_encode($payload . $checksum);
    }

    /**
     * Base58解码
     *
     * @param string $input Base58编码的字符串
     * @return string 返回二进制数据
     */
    private static function base58_decode(string $input): string
    {
        $alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
        $base = strlen($alphabet);
        $decoded = '0';
        for ($i = 0; $i < strlen($input); $i++) {
            $decoded = bcmul($decoded, $base);
            $decoded = bcadd($decoded, strpos($alphabet, $input[$i]));
        }
        $binary = '';
        while (bccomp($decoded, 0) > 0) {
            $binary = chr(bcmod($decoded, 256)) . $binary;
            $decoded = bcdiv($decoded, 256, 0);
        }
        // 为了保持与输入长度一致，添加前导零
        for ($i = 0; $i < strlen($input) && $input[$i] === '1'; $i++) {
            $binary = "\x00" . $binary;
        }
        return $binary;
    }

    /**
     * Base58编码
     *
     * @param string $input 二进制数据
     * @return string 返回Base58编码的字符串
     */
    private static function base58_encode(string $input): string
    {
        $alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
        $base = strlen($alphabet);
        $num = gmp_init(bin2hex($input), 16);
        $encoded = '';
        while (gmp_cmp($num, 0) > 0) {
            list($num, $rem) = gmp_div_qr($num, $base);
            $encoded = $alphabet[gmp_intval($rem)] . $encoded;
        }
        // 添加前导零
        for ($i = 0; isset($input[$i]) && $input[$i] === "\x00"; $i++) {
            $encoded = '1' . $encoded;
        }
        return $encoded;
    }


    /**
     * 把TRX地址转换为ETH地址
     * @param string $address
     * @return array|string|string[]
     * @throws Exception
     */
    public static function TrxAddress2EthAddress(string $address): array|string
    {
        $EthAddress = self::Tto41($address);
        return substr_replace($EthAddress, '0x', 0, 2);
    }









}
