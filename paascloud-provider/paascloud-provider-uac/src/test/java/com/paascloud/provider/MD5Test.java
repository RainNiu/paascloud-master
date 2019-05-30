package com.paascloud.provider;

import com.paascloud.provider.utils.Md5Util;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.keygen.KeyGenerators;


/**
 * The class Md 5 test.
 * @author paascloud.net@gmail.com
 */
@Slf4j
public class MD5Test {
	/**
	 * Md 5.
	 */
	private static void md5() {
		BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
		String encodedPassword = passwordEncoder.encode("123456");
		// $2a$10$b7Ey09KN.UDlMVQePJbBQeJF2fBNmhHCdrc0zChzgkT/VBSnlnerS
		log.info("encodedPassword: " + encodedPassword);
	}

	/**
	 * The entry point of application.
	 *
	 * @param args the input arguments
	 *
	 */
	public static void main(String[] args) {
		md5(); // 使用简单的MD5加密方式

//		String salt = KeyGenerators.string().generateKey();
//		log.info(salt);
//		log.info("salt.length={}", salt.length());
//		String encrypt = Md5Util.encrypt("123456");
//		log.info(encrypt);
	}

}  