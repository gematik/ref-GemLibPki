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
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class CertReader {

    public static X509Certificate readX509(final byte[] file) {
        try {
            final CertificateFactory fact = CertificateFactory.getInstance("X.509");
            try (final ByteArrayInputStream inStream = new ByteArrayInputStream(file)) {
                return (X509Certificate) fact.generateCertificate(inStream);
            }
        } catch (final CertificateException | IOException e) {
            throw new RuntimeException(e);
        }
    }
    
}
