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

import com.amazonaws.cloudhsm.jce.provider.CloudHsmProvider;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttribute;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMap;
import com.amazonaws.cloudhsm.jce.provider.attributes.KeyAttributesMapBuilder;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.util.Base64;
import javax.security.auth.Destroyable;

/**
 * Manage RSA keys.
 */
public class RSAKeyManager {
    public static void main(final String[] args) throws Exception {
        try {
            if (Security.getProvider(CloudHsmProvider.PROVIDER_NAME) == null) {
                Security.addProvider(new CloudHsmProvider());
            }
        } catch (IOException ex) {
            System.out.println(ex);
            return;
        }

        String action = args[0];
        String keyLabel = args[1];

        if (action.equals("create")) {
            System.out.println("Creating key");
            final KeyAttributesMap publicKeyAttrsMap =
                    new KeyAttributesMapBuilder().put(KeyAttribute.TOKEN, true).build();
            final KeyAttributesMap privateKeyAttrsMap =
                    new KeyAttributesMapBuilder()
                            .put(KeyAttribute.EXTRACTABLE, false)
                            .put(KeyAttribute.TOKEN, true)
                            .build();
            AsymmetricKeys.generateRSAKeyPair(
                    2048,
                    keyLabel,
                    publicKeyAttrsMap,
                    privateKeyAttrsMap
            );
        } else if (action.equals("delete")) {
            System.out.println("Deleting key");
            KeyStore keystore = KeyStore.getInstance(CloudHsmProvider.PROVIDER_NAME);
            keystore.load(null, null);
            ((Destroyable) keystore.getKey(String.format("%s:Private", keyLabel), null)).destroy();
            ((Destroyable) keystore.getKey(String.format("%s:Public", keyLabel), null)).destroy();
        }
    }
}
