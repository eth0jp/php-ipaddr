<?php

class IPAddrTest extends PHPUnit_Framework_TestCase
{
	public function test_construct()
	{
		// IPv4 ipaddr
		$ip = new IPAddr("192.168.123.45");
		$this->assertEquals("192.168.123.45", (string)$ip);

		// IPv4 network
		$ip = new IPAddr("192.168.123.45/24");
		$this->assertEquals("192.168.123.0", (string)$ip);

		// IPv6 ipaddr
		$ip = new IPAddr("::1");
		$this->assertEquals("0000:0000:0000:0000:0000:0000:0000:0001", (string)$ip);

		$ip = new IPAddr("::ffff:192.168.123.45");
		$this->assertEquals("0000:0000:0000:0000:0000:ffff:c0a8:7b2d", (string)$ip);

		$ip = new IPAddr("::192.168.123.45");
		$this->assertEquals("0000:0000:0000:0000:0000:0000:c0a8:7b2d", (string)$ip);

		// IPv6 network
		$ip = new IPAddr("2001:0db8:bd05:01d2:288a:1fc0:0001:10ee/48");
		$this->assertEquals("2001:0db8:bd05:0000:0000:0000:0000:0000", (string)$ip);
	}

	public function test_new_ntoh()
	{
		// IPv4
		$ip_bytes = pack('C4', 192, 168, 123, 45);
		$ip = IPAddr::new_ntoh($ip_bytes);
		$this->assertEquals("192.168.123.45", (string)$ip);

		// IPv6
		$ip_bytes = pack('n8', 0x2001, 0x0db8, 0xbd05, 0x01d2, 0x288a, 0x1fc0, 0x0001, 0x10ee);
		$ip = IPAddr::new_ntoh($ip_bytes);
		$this->assertEquals("2001:0db8:bd05:01d2:288a:1fc0:0001:10ee", (string)$ip);
	}

	public function test_is_include()
	{
		// IPv4
		$network = new IPAddr("192.168.123.45/24");
		$this->assertTrue($network->is_include("192.168.123.0"));
		$this->assertTrue($network->is_include("192.168.123.255"));
		$this->assertFalse($network->is_include("192.168.124.45"));

		// IPv6
		$network = new IPAddr("2001:0db8:bd05:01d2:288a:1fc0:0001:10ee/48");
		$this->assertTrue($network->is_include("2001:0db8:bd05:0000:0000:0000:0000:0000"));
		$this->assertTrue($network->is_include("2001:0db8:bd05:ffff:ffff:ffff:ffff:ffff"));
		$this->assertFalse($network->is_include("2001:0db8:bd06:0000:0000:0000:0000:0000"));
	}

	public function test_hton()
	{
		// IPv4
		$ip = new IPAddr("192.168.123.45");
		$ip_bytes = pack('C4', 192, 168, 123, 45);
		$this->assertEquals($ip_bytes, $ip->hton());

		// IPv6
		$ip = new IPAddr("2001:0db8:bd05:01d2:288a:1fc0:0001:10ee");
		$ip_bytes = pack('n8', 0x2001, 0x0db8, 0xbd05, 0x01d2, 0x288a, 0x1fc0, 0x0001, 0x10ee);
		$this->assertEquals($ip_bytes, $ip->hton());
	}

	public function test_is_ipv4()
	{
		// IPv4
		$ip = new IPAddr("192.168.123.45");
		$this->assertTrue($ip->is_ipv4());

		// IPv6
		$ip = new IPAddr("2001:0db8:bd05:01d2:288a:1fc0:0001:10ee");
		$this->assertFalse($ip->is_ipv4());
	}

	public function test_is_ipv6()
	{
		// IPv4
		$ip = new IPAddr("192.168.123.45");
		$this->assertFalse($ip->is_ipv6());

		// IPv6
		$ip = new IPAddr("2001:0db8:bd05:01d2:288a:1fc0:0001:10ee");
		$this->assertTrue($ip->is_ipv6());
	}

	public function test_is_ipv4_mapped()
	{
		// IPv4
		$ip = new IPAddr("192.168.123.45");
		$this->assertFalse($ip->is_ipv4_mapped());

		// IPv6
		$ip = new IPAddr("2001:0db8:bd05:01d2:288a:1fc0:0001:10ee");
		$this->assertFalse($ip->is_ipv4_mapped());

		$ip = new IPAddr("::192.168.123.45");
		$this->assertFalse($ip->is_ipv4_mapped());

		$ip = new IPAddr("::ffff:192.168.123.45");
		$this->assertTrue($ip->is_ipv4_mapped());
	}

	public function test_is_ipv4_compat()
	{
		// IPv4
		$ip = new IPAddr("192.168.123.45");
		$this->assertFalse($ip->is_ipv4_compat());

		// IPv6
		$ip = new IPAddr("2001:0db8:bd05:01d2:288a:1fc0:0001:10ee");
		$this->assertFalse($ip->is_ipv4_compat());

		$ip = new IPAddr("::192.168.123.45");
		$this->assertTrue($ip->is_ipv4_compat());

		$ip = new IPAddr("::ffff:192.168.123.45");
		$this->assertFalse($ip->is_ipv4_compat());
	}

	public function test_native()
	{
		// IPv4
		$ip = new IPAddr("192.168.123.45");
		$this->assertEquals("192.168.123.45", $ip->native());

		// IPv6
		$ip = new IPAddr("::192.168.123.45");
		$this->assertEquals("192.168.123.45", $ip->native());

		$ip = new IPAddr("::ffff:192.168.123.45");
		$this->assertEquals("192.168.123.45", $ip->native());
	}

	public function test_reverse()
	{
		// IPv4
		$ip = new IPAddr("192.168.123.45");
		$this->assertEquals("45.123.168.192.in-addr.arpa", $ip->reverse());

		// IPv6
		$ip = new IPAddr("2001:0db8:bd05:01d2:288a:1fc0:0001:10ee");
		$this->assertEquals("e.e.0.1.1.0.0.0.0.c.f.1.a.8.8.2.2.d.1.0.5.0.d.b.8.b.d.0.1.0.0.2.ip6.arpa", $ip->reverse());

		$ip = new IPAddr("::192.168.123.45");
		$this->assertEquals("d.2.b.7.8.a.0.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa", $ip->reverse());

		$ip = new IPAddr("::ffff:192.168.123.45");
		$this->assertEquals("d.2.b.7.8.a.0.c.f.f.f.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa", $ip->reverse());
	}

	public function test_ip6_arpa()
	{
		// IPv4
		$ip = new IPAddr("192.168.123.45");
		$ip6_arpa = null;
		try {
			$ip6_arpa = $ip->ip6_arpa();
		} catch (IPAddrException $e) {
		}
		$this->assertNull($ip6_arpa);

		// IPv6
		$ip = new IPAddr("2001:0db8:bd05:01d2:288a:1fc0:0001:10ee");
		$this->assertEquals("e.e.0.1.1.0.0.0.0.c.f.1.a.8.8.2.2.d.1.0.5.0.d.b.8.b.d.0.1.0.0.2.ip6.arpa", $ip->ip6_arpa());

		$ip = new IPAddr("::192.168.123.45");
		$this->assertEquals("d.2.b.7.8.a.0.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa", $ip->ip6_arpa());

		$ip = new IPAddr("::ffff:192.168.123.45");
		$this->assertEquals("d.2.b.7.8.a.0.c.f.f.f.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa", $ip->ip6_arpa());
	}

	public function test_ip6_int()
	{
		// IPv4
		$ip = new IPAddr("192.168.123.45");
		$ip6_int = null;
		try {
			$ip6_int = $ip->ip6_int();
		} catch (IPAddrException $e) {
		}
		$this->assertNull($ip6_int);

		// IPv6
		$ip = new IPAddr("2001:0db8:bd05:01d2:288a:1fc0:0001:10ee");
		$this->assertEquals("e.e.0.1.1.0.0.0.0.c.f.1.a.8.8.2.2.d.1.0.5.0.d.b.8.b.d.0.1.0.0.2.ip6.int", $ip->ip6_int());

		$ip = new IPAddr("::192.168.123.45");
		$this->assertEquals("d.2.b.7.8.a.0.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.int", $ip->ip6_int());

		$ip = new IPAddr("::ffff:192.168.123.45");
		$this->assertEquals("d.2.b.7.8.a.0.c.f.f.f.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.int", $ip->ip6_int());
	}

	public function test_succ()
	{
		// IPv4
		$ip = new IPAddr("192.168.123.45");
		$this->assertEquals("192.168.123.46", (string)$ip->succ());

		// IPv6
		$ip = new IPAddr("2001:0db8:bd05:01d2:288a:1fc0:0001:10ee");
		$this->assertEquals("2001:0db8:bd05:01d2:288a:1fc0:0001:10ef", (string)$ip->succ());

		$ip = new IPAddr("::192.168.123.45");
		$this->assertEquals("0000:0000:0000:0000:0000:0000:c0a8:7b2e", (string)$ip->succ());

		$ip = new IPAddr("::ffff:192.168.123.45");
		$this->assertEquals("0000:0000:0000:0000:0000:ffff:c0a8:7b2e", (string)$ip->succ());
	}

	public function test_op_and()
	{
		// IPv4
		$ip_a = new IPAddr("192.168.123.45");
		$ip_b = new IPAddr("192.168.123.45/24");
		$this->assertEquals("192.168.123.0", (string)$ip_a->op_and($ip_b));

		// IPv6
		$ip_a = new IPAddr("2001:0db8:bd05:01d2:288a:1fc0:0001:10ee");
		$ip_b = new IPAddr("2001:0db8:bd05:01d2:288a:1fc0:0001:10ee/48");
		$this->assertEquals("2001:0db8:bd05:0000:0000:0000:0000:0000", (string)$ip_a->op_and($ip_b));
	}

	public function test_op_or()
	{
		// IPv4
		$ip_a = new IPAddr("0.0.0.45");
		$ip_b = new IPAddr("192.168.123.0");
		$this->assertEquals("192.168.123.45", (string)$ip_a->op_or($ip_b));

		// IPv6
		$ip_a = new IPAddr("0000:0000:0000:01d2:288a:1fc0:0001:10ee");
		$ip_b = new IPAddr("2001:0db8:bd05:0000:0000:0000:0000:0000");
		$this->assertEquals("2001:0db8:bd05:01d2:288a:1fc0:0001:10ee", (string)$ip_a->op_or($ip_b));
	}

	public function test_op_right_shift()
	{
		// IPv4
		$ip = new IPAddr("192.168.123.45");
		$this->assertEquals("0.192.168.123", (string)$ip->op_right_shift(8));

		// IPv6
		$ip = new IPAddr("2001:0db8:bd05:01d2:288a:1fc0:0001:10ee");
		$this->assertEquals("0000:2001:0db8:bd05:01d2:288a:1fc0:0001", (string)$ip->op_right_shift(16));

		$ip = new IPAddr("::192.168.123.45");
		$this->assertEquals("0000:0000:0000:0000:0000:0000:0000:c0a8", (string)$ip->op_right_shift(16));

		$ip = new IPAddr("::ffff:192.168.123.45");
		$this->assertEquals("0000:0000:0000:0000:0000:0000:ffff:c0a8", (string)$ip->op_right_shift(16));
	}

	public function test_op_left_shift()
	{
		// IPv4
		$ip = new IPAddr("192.168.123.45");
		$this->assertEquals("168.123.45.0", (string)$ip->op_left_shift(8));

		// IPv6
		$ip = new IPAddr("2001:0db8:bd05:01d2:288a:1fc0:0001:10ee");
		$this->assertEquals("0db8:bd05:01d2:288a:1fc0:0001:10ee:0000", (string)$ip->op_left_shift(16));

		$ip = new IPAddr("::192.168.123.45");
		$this->assertEquals("0000:0000:0000:0000:0000:c0a8:7b2d:0000", (string)$ip->op_left_shift(16));

		$ip = new IPAddr("::ffff:192.168.123.45");
		$this->assertEquals("0000:0000:0000:0000:ffff:c0a8:7b2d:0000", (string)$ip->op_left_shift(16));
	}

	public function test_op_xor()
	{
		// IPv4
		$ip = new IPAddr("192.168.123.45");
		$this->assertEquals("168.123.45.0", (string)$ip->op_left_shift(8));

		// IPv6
		$ip = new IPAddr("2001:0db8:bd05:01d2:288a:1fc0:0001:10ee");
		$this->assertEquals("0db8:bd05:01d2:288a:1fc0:0001:10ee:0000", (string)$ip->op_left_shift(16));

		$ip = new IPAddr("::192.168.123.45");
		$this->assertEquals("0000:0000:0000:0000:0000:c0a8:7b2d:0000", (string)$ip->op_left_shift(16));

		$ip = new IPAddr("::ffff:192.168.123.45");
		$this->assertEquals("0000:0000:0000:0000:ffff:c0a8:7b2d:0000", (string)$ip->op_left_shift(16));
	}

	public function test_op_equal()
	{
		// IPv4
		$ip_a = new IPAddr("192.168.123.45");
		$ip_b = new IPAddr("192.168.123.45");
		$this->assertTrue($ip_a->op_equal($ip_b));

		$ip_a = new IPAddr("192.168.123.45");
		$ip_b = new IPAddr("192.168.123.46");
		$this->assertFalse($ip_a->op_equal($ip_b));

		// IPv6
		$ip_a = new IPAddr("2001:0db8:bd05:01d2:288a:1fc0:0001:10ee");
		$ip_b = new IPAddr("2001:0db8:bd05:01d2:288a:1fc0:0001:10ee");
		$this->assertTrue($ip_a->op_equal($ip_b));

		$ip_a = new IPAddr("2001:0db8:bd05:01d2:288a:1fc0:0001:10ee");
		$ip_b = new IPAddr("2001:0db8:bd05:01d2:288a:1fc0:0001:10ef");
		$this->assertFalse($ip_a->op_equal($ip_b));

		// IPv4 IPv6
		$ip_a = new IPAddr("192.168.123.45");
		$ip_b = new IPAddr("::192.168.123.45");
		$this->assertFalse($ip_a->op_equal($ip_b));
	}

	public function test_coerce_other()
	{
		// IPv4
		$ip = new IPAddr("192.168.123.45");
		$this->assertEquals("IPAddr", get_class(IPAddr::coerce_other($ip)));

		$ip = "192.168.123.45";
		$this->assertEquals("IPAddr", get_class(IPAddr::coerce_other($ip)));

		// IPv6
		$ip = new IPAddr("2001:0db8:bd05:01d2:288a:1fc0:0001:10ee");
		$this->assertEquals("IPAddr", get_class(IPAddr::coerce_other($ip)));

		$ip = "2001:0db8:bd05:01d2:288a:1fc0:0001:10ee";
		$this->assertEquals("IPAddr", get_class(IPAddr::coerce_other($ip)));
	}
}
