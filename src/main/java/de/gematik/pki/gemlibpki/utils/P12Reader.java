/*
 * Copyright (c) 2022 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.pki.gemlibpki.utils;

import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/** Class for unmarshalling a p12 from byte array into an object. */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class P12Reader {

  /**
   * Read byte array, representing a p12 file, to pojo
   *
   * @param p12FileContent p12 as byte array
   * @param p12Password password for p12
   * @return a {@link P12Container}
   */
  public static P12Container getContentFromP12(
      final byte[] p12FileContent, final @NonNull String p12Password) {

    final KeyStore p12;
    try {
      p12 = KeyStore.getInstance("pkcs12", new BouncyCastleProvider());
      p12.load(new ByteArrayInputStream(p12FileContent), p12Password.toCharArray());
      final Enumeration<String> e = p12.aliases();
      if (e.hasMoreElements()) {
        final String alias = e.nextElement();
        final X509Certificate certificate = (X509Certificate) p12.getCertificate(alias);
        final PrivateKey privateKey = (PrivateKey) p12.getKey(alias, p12Password.toCharArray());
        return P12Container.builder().certificate(certificate).privateKey(privateKey).build();
      }
    } catch (final KeyStoreException
        | NoSuchAlgorithmException
        | UnrecoverableKeyException
        | IOException
        | CertificateException e) {
      throw new GemPkiRuntimeException("Konnte .p12 Datei nicht verarbeiten.", e);
    }
    return null;
  }

  /**
   * Read a file from path, representing a p12 file, to pojo
   *
   * @param path path to *.p12 file
   * @param p12Password password for p12
   * @return a {@link P12Container}
   */
  public static P12Container getContentFromP12(final Path path, final @NonNull String p12Password) {
    return getContentFromP12(Utils.readContent(path), p12Password);
  }
}
