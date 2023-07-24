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
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.util.Base64;
import javax.security.auth.Destroyable;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;


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
            // TOKEN true indicates that the key is not temporary, and should be persisted even after the client disconnects
            final KeyAttributesMap publicKeyAttrsMap =
                    new KeyAttributesMapBuilder().put(KeyAttribute.TOKEN, true).build();
            // EXTRACTABLE false indicates that the key is not allowed to be downloaded from the HSM. This is important
            // for the private key to meet NPCI requirements.
            final KeyAttributesMap privateKeyAttrsMap =
                    new KeyAttributesMapBuilder()
                            .put(KeyAttribute.EXTRACTABLE, false)
                            .put(KeyAttribute.TOKEN, true)
                            .build();
            KeyPair kp = AsymmetricKeys.generateRSAKeyPair(
                    2048,
                    keyLabel,
                    publicKeyAttrsMap,
                    privateKeyAttrsMap
            );
            writePemKey(kp, keyLabel);
        } else if (action.equals("delete")) {
            System.out.println("Deleting key");
            KeyStore keystore = KeyStore.getInstance(CloudHsmProvider.PROVIDER_NAME);
            keystore.load(null, null);
            ((Destroyable) keystore.getKey(String.format("%s:Private", keyLabel), null)).destroy();
            ((Destroyable) keystore.getKey(String.format("%s:Public", keyLabel), null)).destroy();
        }
    }

    private static void writePublicKey(KeyPair kp, String outFile) throws Exception {
        Writer out = new FileWriter(outFile + ".pub");
        Base64.Encoder encoder = Base64.getEncoder();
        out.write("-----BEGIN RSA PUBLIC KEY-----\n");
        out.write(encoder.encodeToString(kp.getPublic().getEncoded()));
        out.write("\n-----END RSA PUBLIC KEY-----\n");
        out.close();
    }

    private static void writePemKey(KeyPair kp, String outfile) throws Exception {
        PemObject pemObject = new PemObject("Public Key", kp.getPublic().getEncoded());
        PemWriter pemWriter = new PemWriter(new OutputStreamWriter(new FileOutputStream(outfile + ".pem")));
        try {
            pemWriter.writeObject(pemObject);
        } finally {
            pemWriter.close();
        }
    }
}
