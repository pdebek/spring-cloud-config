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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.context.encrypt.KeyFormatException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.rsa.crypto.RsaKeyHolder;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Dave Syer
 *
 */
@RestController
@RequestMapping("${spring.cloud.config.server.prefix:}")
public class EncryptionController {

    private KeyChain keyChain;
    private TextEncryptorLocator textEncryptorLocator;

    @Autowired
    public EncryptionController(KeyChain keyChain, TextEncryptorLocator textEncryptorLocator) {
        this.keyChain = keyChain;
        this.textEncryptorLocator = textEncryptorLocator;
    }

    @RequestMapping(value = "/key", method = RequestMethod.GET)
	public String getPublicKey() {
        if (!(textEncryptorLocator.locate() instanceof RsaKeyHolder)) {
            throw new KeyNotAvailableException();
        }
        return ((RsaKeyHolder) textEncryptorLocator.locate()).getPublicKey();
    }

	@RequestMapping(value = "/key", method = RequestMethod.POST, params = { "password" })
	public ResponseEntity<Map<String, Object>> uploadKeyStore(
			@RequestParam("file") MultipartFile file,
			@RequestParam("password") String password, @RequestParam("alias") String alias) {
        throw new NotImplementedException();
//		Map<String, Object> body = new HashMap<String, Object>();
//		body.put("status", "OK");
//
//		try {
//			ByteArrayResource resource = new ByteArrayResource(file.getBytes());
//			KeyPair keyPair = new KeyStoreKeyFactory(resource, password.toCharArray())
//					.getKeyPair(alias);
//			textEncryptorLocator = new RsaSecretEncryptor(keyPair);
//            body.put("publicKey", ((RsaKeyHolder) textEncryptorLocator.locate()).getPublicKey());
//        } catch (IOException e) {
//			throw new KeyFormatException();
//		}
//
//		return new ResponseEntity<Map<String, Object>>(body, HttpStatus.CREATED);

	}

	@RequestMapping(value = "/key", method = RequestMethod.POST, params = { "!password" })
	public ResponseEntity<Map<String, Object>> uploadKey(@RequestBody String data,
			@RequestHeader("Content-Type") MediaType type) {

		Map<String, Object> body = new HashMap<String, Object>();
		body.put("status", "OK");

        keyChain.addDefault(stripFormData(data, type, false));

        if (textEncryptorLocator.locate() instanceof RsaKeyHolder) {
            body.put("publicKey", ((RsaKeyHolder) textEncryptorLocator.locate()).getPublicKey());
        }

		return new ResponseEntity<Map<String, Object>>(body, HttpStatus.CREATED);
	}

    public void uploadKey(String data, String application, String profile) {
        this.keyChain.add(EnvironmentAlias.of(application, profile), data);
    }

	@ExceptionHandler(KeyFormatException.class)
	@ResponseBody
	public ResponseEntity<Map<String, Object>> keyFormat() {
		Map<String, Object> body = new HashMap<String, Object>();
		body.put("status", "BAD_REQUEST");
		body.put("description", "Key data not in correct format (PEM or jks keystore)");
		return new ResponseEntity<Map<String, Object>>(body, HttpStatus.BAD_REQUEST);
	}

	@ExceptionHandler(KeyNotAvailableException.class)
	@ResponseBody
	public ResponseEntity<Map<String, Object>> keyUnavailable() {
		Map<String, Object> body = new HashMap<String, Object>();
		body.put("status", "NOT_FOUND");
		body.put("description", "No public key available");
		return new ResponseEntity<Map<String, Object>>(body, HttpStatus.NOT_FOUND);
	}

	@RequestMapping(value = "encrypt/status", method = RequestMethod.GET)
	public Map<String, Object> status() {
        if (textEncryptorLocator.locate() == null) {
            throw new KeyNotInstalledException();
        }
		return Collections.<String, Object> singletonMap("status", "OK");
	}

	@RequestMapping(value = "encrypt", method = RequestMethod.POST)
	public String encrypt(@RequestBody String data,
			@RequestHeader("Content-Type") MediaType type) {
        if (textEncryptorLocator.locate() == null) {
            throw new KeyNotInstalledException();
        }
		data = stripFormData(data, type, false);
        return textEncryptorLocator.locate().encrypt(data);
    }

	@RequestMapping(value = "decrypt", method = RequestMethod.POST)
	public String decrypt(@RequestBody String data,
			@RequestHeader("Content-Type") MediaType type) {
		try {
			data = stripFormData(data, type, true);
            return textEncryptorLocator.locate().decrypt(data);
        } catch (IllegalArgumentException e) {
			throw new InvalidCipherException();
		}
	}

    @RequestMapping(value = "/decrypt/{name}/{profiles}/", method = RequestMethod.POST)
    public String decrypt(@PathVariable String name, @PathVariable String profiles, @RequestBody String data,
                          @RequestHeader("Content-Type") MediaType type) {
        return textEncryptorLocator.locate(name, profiles).decrypt(data);
    }

    @RequestMapping(value = "/encrypt/{name}/{profiles}/", method = RequestMethod.POST)
    public String encrypt(@PathVariable String name, @PathVariable String profiles, @RequestBody String data,
                          @RequestHeader("Content-Type") MediaType type) {
        return textEncryptorLocator.locate(name, profiles).encrypt(data);
    }


	private String stripFormData(String data, MediaType type, boolean cipher) {

		if (data.endsWith("=") && !type.equals(MediaType.TEXT_PLAIN)) {
			try {
				data = URLDecoder.decode(data, "UTF-8");
				if (cipher) {
					data = data.replace(" ", "+");
				}
			}
			catch (UnsupportedEncodingException e) {
				// Really?
			}
			String candidate = data.substring(0, data.length()-1);
			if (cipher) {
				if (data.endsWith("=")) {
					 if (data.length()/2!=(data.length()+1)/2) {
						 try {
							 Hex.decode(candidate);
							 return candidate;
						 } catch (IllegalArgumentException e) {
							 if (Base64.isBase64(data.getBytes())) {
								 return data;
							 }
						 }
					 }
				}
				return data;
			}
			// User posted data with content type form but meant it to be text/plain
			data = candidate;
		}

		return data;

	}

	@ExceptionHandler(KeyNotInstalledException.class)
	@ResponseBody
	public ResponseEntity<Map<String, Object>> notInstalled() {
		Map<String, Object> body = new HashMap<String, Object>();
		body.put("status", "NO_KEY");
		body.put("description", "No key was installed for encryption service");
		return new ResponseEntity<Map<String, Object>>(body, HttpStatus.NOT_FOUND);
	}

	@ExceptionHandler(InvalidCipherException.class)
	@ResponseBody
	public ResponseEntity<Map<String, Object>> invalidCipher() {
		Map<String, Object> body = new HashMap<String, Object>();
		body.put("status", "INVALID");
		body.put("description", "Text not encrypted with this key");
		return new ResponseEntity<Map<String, Object>>(body, HttpStatus.BAD_REQUEST);
	}
}

@SuppressWarnings("serial")
class KeyNotInstalledException extends RuntimeException {
}

@SuppressWarnings("serial")
class KeyNotAvailableException extends RuntimeException {
}

@SuppressWarnings("serial")
class InvalidCipherException extends RuntimeException {
}
