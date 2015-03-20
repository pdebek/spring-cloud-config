/*
 * Copyright 2013-2014 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.cloud.config.server;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.springframework.http.MediaType.TEXT_PLAIN;

import java.security.KeyStoreException;
import java.util.Collections;

import org.junit.Test;
import org.springframework.cloud.bootstrap.encrypt.KeyProperties;
import org.springframework.cloud.config.environment.Environment;
import org.springframework.cloud.config.environment.PropertySource;
import org.springframework.cloud.config.server.EncryptionController;
import org.springframework.cloud.config.server.InvalidCipherException;
import org.springframework.cloud.config.server.KeyNotInstalledException;
import org.springframework.cloud.context.encrypt.KeyFormatException;
import org.springframework.core.io.UrlResource;
import org.springframework.http.MediaType;
import org.springframework.security.rsa.crypto.RsaSecretEncryptor;

/**
 * @author Dave Syer
 *
 */
public class EncryptionControllerTests {

	private EncryptionController controller = new EncryptionController();

	@Test(expected = KeyNotInstalledException.class)
	public void cannotDecryptWithoutKey() {
		controller.decrypt("foo", TEXT_PLAIN);
	}

	@Test(expected = KeyFormatException.class)
	public void cannotUploadPublicKey() {
		controller.uploadKey("ssh-rsa ...", TEXT_PLAIN);
	}

	@Test(expected = KeyFormatException.class)
	public void cannotUploadPublicKeyPemFormat() {
		controller.uploadKey("---- BEGIN RSA PUBLIC KEY ...", TEXT_PLAIN);
	}

	@Test(expected = InvalidCipherException.class)
	public void invalidCipher() {
		controller.uploadKey("foo", TEXT_PLAIN);
		controller.decrypt("foo", TEXT_PLAIN);
	}

	@Test
	public void sunnyDaySymmetricKey() {
		controller.uploadKey("foo", TEXT_PLAIN);
		String cipher = controller.encrypt("foo", TEXT_PLAIN);
		assertEquals("foo", controller.decrypt(cipher, TEXT_PLAIN));
	}

	@Test
	public void sunnyDayRsaKey() {
		controller.setEncryptor(new RsaSecretEncryptor());
		String cipher = controller.encrypt("foo", TEXT_PLAIN);
		assertEquals("foo", controller.decrypt(cipher, TEXT_PLAIN));
	}

	@Test
	public void publicKey() {
		controller.setEncryptor(new RsaSecretEncryptor());
		String key = controller.getPublicKey();
		assertTrue("Wrong key format: " + key, key.startsWith("ssh-rsa"));
	}

	@Test
	public void formDataIn() {
		controller.setEncryptor(new RsaSecretEncryptor());
		// Add space to input
		String cipher = controller.encrypt("foo bar=", MediaType.APPLICATION_FORM_URLENCODED);
		String decrypt = controller.decrypt(cipher + "=", MediaType.APPLICATION_FORM_URLENCODED);
		assertEquals("Wrong decrypted plaintext: " + decrypt, "foo bar", decrypt);
	}

//	@Test
//	public void decryptEnvironment() {
//		controller.uploadKey("foo", TEXT_PLAIN);
//		String cipher = controller.encrypt("foo", TEXT_PLAIN);
//		Environment environment = new Environment("foo", "bar");
//		environment.add(new PropertySource("spam", Collections
//				.<Object, Object> singletonMap("my", "{cipher}" + cipher)));
//		Environment result = controller.decrypt(environment);
//		assertEquals("foo", result.getPropertySources().get(0).getSource().get("my"));
//	}

    @Test
    public void shouldDecryptEnvironmentUsingAppropriateEncryptionKey() throws KeyStoreException {
        // given
        KeyProperties.KeyStore properties = new KeyProperties.KeyStore();
        properties.setLocation(new UrlResource(EncryptionControllerTests.class.getClassLoader().getResource("aes-keystore.jck")));
        properties.setPassword("password");
        controller.setKeyChain(new KeyChain(properties));

        Environment environment1 = new Environment("name1", "label1");
        controller.uploadKey("foo", environment1.getName(), environment1.getProfiles()[0]);

        Environment environment2 = new Environment("name2", "label2");
        controller.uploadKey("foo", environment2.getName(), environment2.getProfiles()[0]);

        // when
        String key = "secret";
        
        String secret1 = "secret1";
        String encrypted1 = controller.encrypt(secret1, environment1.getName(), environment1.getProfiles()[0], MediaType.TEXT_PLAIN);
        
        environment1.add(new PropertySource("spam", Collections
                .<Object, Object> singletonMap(key, "{cipher}" + encrypted1)));

        String secret2 = "secret2";
        String encrypted2 = controller.encrypt(secret2,  environment2.getName(), environment2.getProfiles()[0], MediaType.TEXT_PLAIN);
        environment2.add(new PropertySource("spam", Collections
                .<Object, Object> singletonMap(key, "{cipher}" + encrypted2)));


        // then
        assertEquals(secret1, controller.decrypt(secret1, environment1.getName(), environment1.getProfiles()[0], MediaType.TEXT_PLAIN));
        assertEquals(secret2, controller.decrypt(secret2, environment2.getName(), environment2.getProfiles()[0], MediaType.TEXT_PLAIN));
    }


	@Test
	public void randomizedCipher() {
		controller.uploadKey("foo", TEXT_PLAIN);
		String cipher = controller.encrypt("foo", TEXT_PLAIN);
		assertNotEquals(cipher, controller.encrypt("foo", TEXT_PLAIN));
	}

}
