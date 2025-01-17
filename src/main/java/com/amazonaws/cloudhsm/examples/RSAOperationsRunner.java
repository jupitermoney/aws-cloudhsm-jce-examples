/*
 * Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package com.amazonaws.cloudhsm.examples;

import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMap;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMapBuilder;
import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * Demonstrate basic RSA operations.
 */
public class RSAOperationsRunner {
    /**
     * Encrypt plainText using the passed transformation.
     * Supported transformations are documented here: https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-lib-supported.html
     *
     * @param transformation
     * @param key
     * @param plainText
     * @return
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static byte[] encrypt(String transformation, Key key, byte[] plainText)
            throws InvalidKeyException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            NoSuchPaddingException,
            IllegalBlockSizeException,
            BadPaddingException {
        Cipher encCipher = Cipher.getInstance(transformation, CloudHsmProvider.PROVIDER_NAME);
        encCipher.init(Cipher.ENCRYPT_MODE, key);
        return encCipher.doFinal(plainText);
    }

    /**
     * Decrypt cipherText using the passed transformation.
     * Supported transformations are documented here: https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-lib-supported.html
     *
     * @param transformation
     * @param key
     * @param cipherText
     * @return
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static byte[] decrypt(String transformation, Key key, byte[] cipherText)
            throws InvalidKeyException,
            NoSuchAlgorithmException,
            NoSuchProviderException,
            NoSuchPaddingException,
            IllegalBlockSizeException,
            BadPaddingException {
        Cipher decCipher = Cipher.getInstance(transformation, CloudHsmProvider.PROVIDER_NAME);
        decCipher.init(Cipher.DECRYPT_MODE, key);
        return decCipher.doFinal(cipherText);
    }

    /**
     * Sign a message using the passed signing algorithm.
     * Supported signature types are documented here: https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-lib-supported.html
     *
     * @param message
     * @param key
     * @param signingAlgorithm
     * @return
     * @throws SignatureException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static byte[] sign(byte[] message, PrivateKey key, String signingAlgorithm)
            throws SignatureException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        Signature sig = Signature.getInstance(signingAlgorithm, "CloudHSM");
        sig.initSign(key);
        sig.update(message);
        return sig.sign();
    }

    /**
     * Verify the signature of a message.
     * Supported signature types are documented here: https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-lib-supported.html
     *
     * @param message
     * @param signature
     * @param publicKey
     * @param signingAlgorithm
     * @return
     * @throws SignatureException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static boolean verify(byte[] message, byte[] signature, PublicKey publicKey, String signingAlgorithm)
            throws SignatureException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        Signature sig = Signature.getInstance(signingAlgorithm, "CloudHSM");
        sig.initVerify(publicKey);
        sig.update(message);
        return sig.verify(signature);
    }

    public static void main(final String[] args) throws Exception {
        try {
            if (Security.getProvider(CloudHsmProvider.PROVIDER_NAME) == null) {
                Security.addProvider(new CloudHsmProvider());
            }
        } catch (IOException ex) {
            System.out.println(ex);
            return;
        }

        String keyLabel = args[0];
        String plainText = "This is a sample Plain Text Message!";
        String transformation = "RSA/ECB/PKCS1Padding";

        KeyStore keystore = KeyStore.getInstance(CloudHsmProvider.PROVIDER_NAME);
        keystore.load(null, null);
        Key privateKey = keystore.getKey(String.format("%s:Private", keyLabel), null);
        Key publicKey = keystore.getKey(String.format("%s:Public", keyLabel), null);

        System.out.println("Performing RSA Encryption Operation");
        byte[] cipherText = null;
        cipherText = encrypt(transformation, publicKey, plainText.getBytes(
            StandardCharsets.UTF_8));

        System.out.println("Encrypted plaintext = " + Base64.getEncoder().encodeToString(cipherText));

        byte[] decryptedText = decrypt(transformation, privateKey, cipherText);
        System.out.println("Decrypted text = " + new String(decryptedText, StandardCharsets.UTF_8));

        // RSA sign and verify.
        {
            String signingAlgorithm = "SHA512withRSA";
            byte[] signature = sign(plainText.getBytes(StandardCharsets.UTF_8), (PrivateKey) privateKey, signingAlgorithm);
            System.out.println("RSA signature = " + Base64.getEncoder().encodeToString(signature));

            if (verify(plainText.getBytes(StandardCharsets.UTF_8), signature, (PublicKey) publicKey, signingAlgorithm)) {
                System.out.println("Signature verified");
            } else {
                System.out.println("Signature is invalid!");
            }
        }

        // RSA PSS sign and verify.
        {
            String signingAlgorithm = "SHA512withRSA/PSS";
            byte[] signature = sign(plainText.getBytes(StandardCharsets.UTF_8), (PrivateKey) privateKey, signingAlgorithm);
            System.out.println("RSA PSS signature = " + Base64.getEncoder().encodeToString(signature));

            if (verify(plainText.getBytes(StandardCharsets.UTF_8), signature, (PublicKey) publicKey, signingAlgorithm)) {
                System.out.println("Signature verified");
            } else {
                System.out.println("Signature is invalid!");
            }
        }
    }
}
