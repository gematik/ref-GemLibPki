/*
 * Copyright (c) 2021 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.pki.utils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class P12Reader {

    private static final BouncyCastleProvider BOUNCY_CASTLE_PROVIDER = new BouncyCastleProvider();

    public static P12Content getContentFromP12(final byte[] p12FileContent, final String p12Password) {

        final KeyStore p12;
        try {
            p12 = KeyStore.getInstance("pkcs12", BOUNCY_CASTLE_PROVIDER);
            p12.load(new ByteArrayInputStream(p12FileContent), p12Password.toCharArray());
            final Enumeration<String> e = p12.aliases();
            while (e.hasMoreElements()) {
                final String alias = e.nextElement();
                final X509Certificate certificate = (X509Certificate) p12.getCertificate(alias);
                final PrivateKey privateKey = (PrivateKey) p12.getKey(alias, p12Password.toCharArray());
                return new P12Content(certificate, privateKey);
            }
        } catch (final KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | IOException | CertificateException e) {
            throw new RuntimeException("Cannot read p12 file.", e);
        }
        return null;

    }
}
