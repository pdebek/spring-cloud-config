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

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.springframework.cloud.bootstrap.encrypt.KeyProperties;
import org.springframework.cloud.config.environment.Environment;
import org.springframework.cloud.config.environment.PropertySource;
import org.springframework.cloud.context.encrypt.EncryptorFactory;
import org.springframework.core.io.UrlResource;
import org.springframework.http.MediaType;

/**
 * @author Dave Syer
 *
 */
public class EncryptionControllerTests {

	private EncryptionController controller;
    private EncryptorFactory encryptorFactory = new EncryptorFactory();
    private IKeyChain emptyKeyChain = new EmptyKeyChain();

    @Before
    public void setup() {
        KeyProperties.KeyStore properties = new KeyProperties.KeyStore();
        properties.setLocation(new UrlResource(EncryptionControllerTests.class.getClassLoader().getResource("aes-keystore.jck")));
        properties.setPassword("password");
        properties.setAlias("default");
        KeyChain keyChain = new KeyChain(properties);
        this.controller = new EncryptionController(keyChain, new TextEncryptorLocator(encryptorFactory, keyChain));
        controller.uploadKey("aa", MediaType.TEXT_PLAIN);
    }


	@Test(expected = KeyNotInstalledException.class)
	public void cannotDecryptWithoutKey() {
		// given
        TextEncryptorLocator locator = new TextEncryptorLocator(encryptorFactory, emptyKeyChain);
        EncryptionController controller = new EncryptionController(emptyKeyChain, locator);

        // when
        controller.decrypt("foo", TEXT_PLAIN);
	}

	@Test(expected = InvalidCipherException.class)
	public void invalidCipher() {
		controller.uploadKey("foo", TEXT_PLAIN);
		controller.decrypt("foo", TEXT_PLAIN);
	}

	@Test
	public void shouldDecryptSelfEncryptedDataUsingUploadedKey() {
		controller.uploadKey("foo", TEXT_PLAIN);
		String cipher = controller.encrypt("foo", TEXT_PLAIN);
		assertEquals("foo", controller.decrypt(cipher, TEXT_PLAIN));
	}

	@Test
	public void shouldDecryptSelfEncryptedData() {
		String cipher = controller.encrypt("foo", TEXT_PLAIN);
		assertEquals("foo", controller.decrypt(cipher, TEXT_PLAIN));
	}

	@Ignore("RSA is not supported yet")
    @Test
	public void publicKey() {
		String key = controller.getPublicKey();
		assertTrue("Wrong key format: " + key, key.startsWith("ssh-rsa"));
	}

    @Test(expected = KeyNotAvailableException.class)
    public void shouldReturnKeyNotAvailableIfDefaultPublicKeyIsNotInstalled() {
        controller.getPublicKey();
    }

	@Test
	public void formDataIn() {
        // Add space to input
        String cipher = controller.encrypt("foo bar=", MediaType.APPLICATION_FORM_URLENCODED);
        String decrypt = controller.decrypt(cipher + "=", MediaType.APPLICATION_FORM_URLENCODED);
        assertEquals("Wrong decrypted plaintext: " + decrypt, "foo bar", decrypt);
    }

    @Test
    public void shouldDecryptEnvironmentUsingAppropriateEncryptionKey() throws KeyStoreException {
        // given
        Environment environment1 = new Environment("name1", "label1");
        controller.uploadKey("foo", environment1.getName(), environment1.getProfiles()[0]);

        Environment environment2 = new Environment("name2", "label2");
        controller.uploadKey("foo", environment2.getName(), environment2.getProfiles()[0]);

        // when
        String key = "secret";
        
        String secret1 = "secret1";
        String encrypted1 = controller.encrypt(environment1.getName(), environment1.getProfiles()[0], secret1, MediaType.TEXT_PLAIN);
        
        environment1.add(new PropertySource("spam", Collections
                .<Object, Object> singletonMap(key, "{cipher}" + encrypted1)));

        String secret2 = "secret2";
        String encrypted2 = controller.encrypt(environment2.getName(), environment2.getProfiles()[0], secret2, MediaType.TEXT_PLAIN);
        environment2.add(new PropertySource("spam", Collections
                .<Object, Object> singletonMap(key, "{cipher}" + encrypted2)));


        // then
        assertEquals(secret1, controller.decrypt(environment1.getName(), environment1.getProfiles()[0], encrypted1, MediaType.TEXT_PLAIN));
        assertEquals(secret2, controller.decrypt(environment2.getName(), environment2.getProfiles()[0], encrypted2, MediaType.TEXT_PLAIN));
    }


	@Test
	public void randomizedCipher() {
		controller.uploadKey("foo", TEXT_PLAIN);
		String cipher = controller.encrypt("foo", TEXT_PLAIN);
		assertNotEquals(cipher, controller.encrypt("foo", TEXT_PLAIN));
	}

}
