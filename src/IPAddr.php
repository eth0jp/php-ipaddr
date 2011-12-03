<?php

require_once 'IPAddr/Exception.php';
require_once 'Math/BigInteger.php';


class IPAddr
{
	// const
	protected static $HEX_FFFF = null;
	protected static $HEX_FFFFFFFF = null;
	protected static $HEX_FFFFFFFFFFFFFFFFFFFFFFFF = null;
	protected static $HEX_FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF = null;
	protected static $HEX_FFFF00000000 = null;

	protected static $IN4MASK = null;
	protected static $IN6MASK = null;
	const IN6FORMAT = "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x";

	// var
	protected $_addr = null;
	protected $_mask_addr = null;
	protected $_family = null;

	// Creates a new ipaddr object either from a human readable IP
	// address representation in string, or from a packed in_addr value
	// followed by an address family.
	//
	// In the former case, the following are the valid formats that will
	// be recognized: "address", "address/prefixlen" and "address/mask",
	// where IPv6 address may be enclosed in square brackets (`[' and
	// `]').  If a prefixlen or a mask is specified, it returns a masked
	// IP address.  Although the address family is determined
	// automatically from a specified string, you can specify one
	// explicitly by the optional second argument.
	//
	// Otherwise an IP address is generated from a packed in_addr value
	// and an address family.
	//
	// The IPAddr class defines many methods and operators, and some of
	// those, such as &, |, include? and ==, accept a string, or a packed
	// in_addr value instead of an IPAddr object.
	public function __construct($addr='::', $family=null)
	{
		// setup static properties
		if (is_null(self::$IN4MASK)) {
			self::$HEX_FFFF = new Math_BigInteger("65535");
			self::$HEX_FFFFFFFF = new Math_BigInteger("4294967295");
			self::$HEX_FFFFFFFFFFFFFFFFFFFFFFFF = new Math_BigInteger("79228162514264337593543950335");
			self::$HEX_FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF = new Math_BigInteger("340282366920938463463374607431768211455");
			self::$HEX_FFFF00000000 = new Math_BigInteger("281470681743360");

			self::$IN4MASK = self::$HEX_FFFFFFFF;
			self::$IN6MASK = self::$HEX_FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;
		}

		if ($addr instanceof self) {
			switch ($family) {
			case AF_INET:
			case AF_INET6:
				$this->_set($addr->to_i(), $family);
				$this->_mask_addr = $family==AF_INET ? self::$IN4MASK : self::$IN6MASK;
				break;
			default:
				throw new IPAddrException(sprintf("unsupported address family: %s", $family));
			}
		} else {
			@list($prefix, $prefixlen) = explode('/', $addr, 2);
			if (preg_match('/^\[(.*)\]$/', $prefix, $m)) {
				$prefix = $m[1];
				$family = AF_INET6;
			}
			$this->_addr = null;
			$this->_family = null;
			if (is_null($family) || $family==AF_INET) {
				$this->_addr = self::in_addr($prefix);
				if ($this->_addr) {
					$this->_family = AF_INET;
				}
			}
			if (!$this->_addr && (is_null($family) || $family==AF_INET6)) {
				$this->_addr = $this->in6_addr($prefix);
				$this->_family = AF_INET6;
			}
			if (isset($family) && $this->_family!=$family) {
				throw new IPAddrException("address family mismatch");
			}
			if ($prefixlen) {
				$this->mask($prefixlen);
			} else {
				$this->_mask_addr = $this->_family==AF_INET ? self::$IN4MASK : self::$IN6MASK;
			}
		}
	}

	// Creates a new ipaddr containing the given network byte ordered
	// string form of an IP address.
	public static function new_ntoh($addr)
	{
		return new self(self::ntop($addr));
	}

	// Convert a network byte ordered string form of an IP address into
	// human readable form.
	public static function ntop($addr)
	{
		switch (strlen($addr)) {
		case 4:
			$s = implode('.', unpack('C4', $addr));
			break;
		case 16:
			$args = array_merge(array(self::IN6FORMAT), unpack('n8', $addr));
			$s = call_user_func_array('sprintf', $args);
			break;
		default:
			throw new IPAddrException("unsupported address family");
		}
		return $s;
	}

	// Returns a new ipaddr built by masking IP address with the given
	// prefixlen/netmask. (e.g. 8, 64, "255.255.255.0", etc.)
	public function mask($prefixlen)
	{
		if (is_string($prefixlen)) {
			if (ctype_digit($prefixlen)) {
				$prefixlen = (int)$prefixlen;
			} else {
				$m = new self($prefixlen);
				if ($m->_family!=$this->_family) {
					throw new IPAddrException("address family is not same");
				}
				$this->_mask_addr = $m->to_i();
				$this->_addr = $this->_addr->bitwise_and($this->_mask_addr);
				return $this;
			}
		}
		switch ($this->_family) {
		case AF_INET:
			if ($prefixlen < 0 || 32 < $prefixlen) {
				throw new IPAddrException("invalid length");
			}
			$masklen = 32 - $prefixlen;
			//$this->_mask_addr = (self::IN4MASK >> $masklen) << $masklen;
			$this->_mask_addr = self::$IN4MASK->bitwise_rightShift($masklen)->bitwise_leftShift($masklen);
			break;
		case AF_INET6:
			if ($prefixlen < 0 || 128 < $prefixlen) {
				throw new IPAddrException("invalid length");
			}
			$masklen = 128 - $prefixlen;
			//$this->_mask_addr = (self::IN6MASK >> $masklen) << $masklen;
			$this->_mask_addr = self::$IN6MASK->bitwise_rightShift($masklen)->bitwise_leftShift($masklen);
			break;
		defualt:
			throw new IPAddrException("unsupported address family");
		}
		//$this->_addr = ($this->_addr >> $masklen) << $masklen;
		$this->_addr = $this->_addr->bitwise_rightShift($masklen)->bitwise_leftShift($masklen);
		return $this;
	}

	//  Returns true if the given ipaddr is in the range.
	// 
	//  e.g.:
	//    require 'ipaddr'
	//    net1 = IPAddr.new("192.168.2.0/24")
	//    net2 = IPAddr.new("192.168.2.100")
	//    net3 = IPAddr.new("192.168.3.0")
	//    p net1.include?(net2)>#=> true
	//    p net1.include?(net3)>#=> false
	public function is_include($other)
	{
		$other = self::coerce_other($other);
		if ($this->is_ipv4_mapped()) {
			if ($this->_mask_addr->bitwise_rightShift(32)->compare(self::$HEX_FFFFFFFFFFFFFFFFFFFFFFFF)!=0) {
				return false;
			}
			$mask_addr = $this->_mask_addr->bitwise_and(self::$IN4MASK);
			$addr = $this->_addr->bitwise_and(self::$IN4MASK);
			$family = AF_INET;
		} else {
			$mask_addr = $this->_mask_addr;
			$addr = $this->_addr;
			$family = $this->_family;
		}
		if ($other->is_ipv4_mapped()) {
			$other_addr = $other->_addr->bitwise_and(self::$IN4MASK);
			$other_family = AF_INET;
		} else {
			$other_addr = $other->_addr;
			$other_family = $other->_family;
		}

		if ($family!=$other_family) {
			return false;
		}
		return $addr->bitwise_and($mask_addr)->compare($other_addr->bitwise_and($mask_addr))==0;
	}

	// Returns the integer representation of the ipaddr.
	public function to_i()
	{
		return $this->_addr;
	}

	// Returns a string containing the IP address representation.
	public function to_s()
	{
		$str = $this->__toString();
		if ($this->is_ipv4()) {
			return $str;
		}

		$str = preg_replace('/(^|:)0{1,3}([0-9a-f]+)/i', '\1\2', $str);
		for ($i=8; 2<$i; $i--) {
			$search = implode(':', array_fill(0, $i, '0'));
			if (strpos($str, $search)!==false) {
				$exp = explode($search, $str, 2);
				$exp[0] = trim($exp[0], ':');
				$exp[1] = trim($exp[1], ':');
				$str = $exp[0] . '::' . $exp[1];
				break;
			}
		}

		if (preg_match('/^::(ffff:)?([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i', $str, $m)) {
			$m[2] = hexdec($m[2]);
			$m[3] = hexdec($m[3]);
			$str = sprintf('::%s%d.%d.%d.%d', $m[1], $m[2]/256, $m[2]%256, $m[3]/256, $m[3]%256);
		}

		return $str;
	}

	public function getFamily()
	{
		return $this->_family;
	}

	// Returns a network byte ordered string form of the IP address.
	public function hton()
	{
		switch ($this->_family) {
		case AF_INET:
			return pack('N', (int)(string)($this->_addr));
		case AF_INET6:
			$sections = array();
			for ($i=0; $i<8; $i++) {
				$sections[] = (int)(string)($this->_addr->bitwise_rightShift($i*16)->bitwise_and(self::$HEX_FFFF));
			}
			$args = array_merge(array('n8'), array_reverse($sections));
			return call_user_func_array('pack', $args);
		default:
			throw new IPAddrException("unsupported address family");
		}
	}

	// Returns true if the ipaddr is an IPv4 address.
	public function is_ipv4()
	{
		return $this->_family==AF_INET;
	}

	// Returns true if the ipaddr is an IPv6 address.
	public function is_ipv6()
	{
		return $this->_family==AF_INET6;
	}

	// Returns true if the ipaddr is an IPv4-mapped IPv6 address.
	public function is_ipv4_mapped()
	{
		return $this->is_ipv6() && $this->_addr->bitwise_rightShift(32)->compare(self::$HEX_FFFF)==0;
	}

	// Returns true if the ipaddr is an IPv4-compatible IPv6 address.
	public function is_ipv4_compat()
	{
		if (!$this->is_ipv6() || 0<$this->_addr->bitwise_rightShift(32)->compare(new Math_BigInteger("0"))) {
			return false;
		}
		$a = (int)(string)($this->_addr->bitwise_and(self::$IN4MASK));
		return $a!=0 && $a!=1;
	}

	// Returns a new ipaddr built by converting the native IPv4 address
	// into an IPv4-mapped IPv6 address.
	public function ipv4_mapped()
	{
		if (!$this->ipv4()) {
			throw new IPAddrException("not an IPv4 address");
		}
		$clone = clone $this;
		return $clone->_set($this->_addr->bitwise_or(self::$HEX_FFFF00000000), AF_INET6);
	}

	// Returns a new ipaddr built by converting the native IPv4 address
	// into an IPv4-compatible IPv6 address.
	public function ipv4_compact()
	{
		if (!$this->ipv4()) {
			throw new IPAddrException("not an IPv4 address");
		}
		$clone = clone $this;
		return $clone->_set($this->_addr, AF_INET6);
	}

	// Returns a new ipaddr built by converting the IPv6 address into a
	// native IPv4 address.  If the IP address is not an IPv4-mapped or
	// IPv4-compatible IPv6 address, returns self.
	public function native()
	{
		if (!$this->is_ipv4_mapped() && !$this->is_ipv4_compat()) {
			return $this;
		}
		$clone = clone $this;
		//return $clone->_set($this->_addr & self::IN4MASK, AF_INET);
		return $clone->_set($this->_addr->bitwise_and(self::$IN4MASK), AF_INET);
	}

	// Returns a string for DNS reverse lookup.  It returns a string in
	// RFC3172 form for an IPv6 address.
	public function reverse()
	{
		switch ($this->_family) {
		case AF_INET:
			return $this->_reverse() . '.in-addr.arpa';
		case AF_INET6:
			return $this->ip6_arpa();
		default:
			throw new IPAddrException("unsupported address family");
		}
	}

	// Returns a string for DNS reverse lookup compatible with RFC3172.
	public function ip6_arpa()
	{
		if (!$this->is_ipv6()) {
			throw new IPAddrException("not an IPv6 address");
		}
		return $this->_reverse() . '.ip6.arpa';
	}

	// Returns a string for DNS reverse lookup compatible with RFC1886.
	public function ip6_int()
	{
		if (!$this->is_ipv6()) {
			throw new IPAddrException("not an IPv6 address");
		}
		return $this->_reverse() . '.ip6.int';
	}

	// Returns the successor to the ipaddr.
	public function succ()
	{
		$clone = clone $this;
		return $clone->_set($this->_addr->add(new Math_BigInteger(1)), $this->_family);
	}

	protected function _set($addr, $family=null)
	{
		switch (isset($family) ? $family : $this->_family) {
		case AF_INET:
			if ($addr->compare(new Math_BigInteger("0"))<0 || 0<$addr->compare(self::$IN4MASK)) {
				throw new IPAddrException("invalid address");
			}
			break;
		case AF_INET6:
			if ($addr->compare(new Math_BigInteger("0"))<0 || 0<$addr->compare(self::$IN6MASK)) {
				throw new IPAddrException("invalid address");
			}
			break;
		default:
			throw new IPAddrException("unsupported address family");
		}
		$this->_addr = $addr;
		if (isset($family)) {
			$this->_family = $family;
		}
		return $this;
	}

	protected function _addr_mask($addr)
	{
		switch ($this->_family) {
		case AF_INET:
			return $addr->bitwise_and(self::$IN4MASK);
		case AF_INET6:
			return $addr->bitwise_and(self::$IN6MASK);
		default:
			throw new IPAddrException("unsupported address family");
		}
	}

	protected function _reverse()
	{
		switch ($this->_family) {
		case AF_INET:
			return implode('.', array_reverse(explode('.', long2ip($this->_addr))));
		case AF_INET6:
			$hex = "";
			$tmp = $this->_addr;
			for ($i=0; $i<8; $i++) {
				$section = (int)(string)$tmp->bitwise_and(self::$HEX_FFFF);
				$section = sprintf("%04x", $section);
				$hex = $section . $hex;
				$tmp = $tmp->bitwise_rightShift(16);
			}
			return implode('.', array_reverse(str_split($hex)));
		default:
			throw new IPAddrException("unsupported address family");
		}
	}

	// Returns a string containing the IP address representation in
	// canonical form.
	public function __toString()
	{
		switch ($this->_family) {
		case AF_INET:
			return long2ip($this->_addr);
		case AF_INET6:
			$sections = array();
			$tmp = $this->_addr;
			for ($i=0; $i<8; $i++) {
				$section = (int)(string)$tmp->bitwise_and(self::$HEX_FFFF);
				$section = sprintf("%04x", $section);
				array_unshift($sections, $section);
				$tmp = $tmp->bitwise_rightShift(16);
			}
			return implode(':', $sections);
		default:
			throw new IPAddrException("unsupported address family");
		}
	}


	// Returns a new ipaddr built by bitwise AND.
	public function op_and($other)
	{
		$clone = clone $this;
		return $clone->_set($this->_addr->bitwise_and(self::coerce_other($other)->to_i()));
	}

	// Returns a new ipaddr built by bitwise OR.
	public function op_or($other)
	{
		$clone = clone $this;
		return $clone->_set($this->_addr->bitwise_or(self::coerce_other($other)->to_i()));
	}

	// Returns a new ipaddr built by bitwise right-shift.
	public function op_right_shift($num)
	{
		$clone = clone $this;
		return $clone->_set($this->_addr->bitwise_rightShift($num));
	}

	// Returns a new ipaddr built by bitwise left shift.
	public function op_left_shift($num)
	{
		$clone = clone $this;
		return $clone->_set($this->_addr_mask($this->_addr->bitwise_leftShift($num)));
	}

	// Returns a new ipaddr built by bitwise negation.
	public function op_xor()
	{
		$clone = clone $this;
		$mask = $this->family==AF_INET ? self::$IN4MASK : self::$IN6MASK;
		return $clone->_set($this->_addr_mask($this->_addr->bitwise_xor($mask)));
	}

	// Returns true if two ipaddrs are equal.
	public function op_equal($other)
	{
		$other = self::coerce_other($other);
		return $this->getFamily()==$other->getFamily() && $this->to_i()==$other->to_i();
	}


	public static function coerce_other($other)
	{
		if ($other instanceof self) {
			return $other;
		} else if (is_string($other)) {
			return new self($other);
		} else {
			return new self($other, $this->_family);
		}
	}

	protected static function in_addr($addr)
	{
		if (preg_match('/^\d+\.\d+\.\d+\.\d+$/', $addr)) {
			return new Math_BigInteger(ip2long($addr));
		}
		return null;
	}

	protected static function in6_addr($left)
	{
		if (preg_match('/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i', $left, $m)) {
			return self::in_addr($m[1])->add(self::$HEX_FFFF00000000);
		} else if (preg_match('/^::(\d+\.\d+\.\d+\.\d+)$/', $left, $m)) {
			return self::in_addr($m[1]);
		} else if (preg_match('/[^0-9a-f:]/i', $left)) {
			throw new IPAddrException("invalid address");
		} else if (preg_match('/^(.*)::(.*)$/', $left, $m)) {
			$left = $m[1];
			$right = $m[2];
		} else {
			$right = '';
		}

		$l = explode(':', $left);
		for ($i=count($l)-1; 0<=$i; $i--) {
			if (strlen($l[$i])==0) {
				unset($l[$i]);
			}
		}
		$r = explode(':', $right);
		for ($i=count($r)-1; 0<=$i; $i--) {
			if (strlen($r[$i])==0) {
				unset($r[$i]);
			}
		}

		$rest = 8 - count($l) - count($r);
		if ($rest < 0) {
			return null;
		}
		$c = 0<$rest ? array_fill(0, $rest, 0) : array();
		$sections = array_merge($l, $c, $r);
		$result = new Math_BigInteger();
		foreach ($sections as $section) {
			$section = hexdec($section);
			$result = $result->bitwise_leftShift(16)->bitwise_or(new Math_BigInteger($section));
		}
		return $result;
	}
}
