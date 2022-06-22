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
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Objects;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.NonNull;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class CertReader {

  public static X509Certificate readX509(final byte[] file) {
    try {
      final CertificateFactory fact = CertificateFactory.getInstance("X.509");
      try (final ByteArrayInputStream inStream = new ByteArrayInputStream(file)) {
        return (X509Certificate) fact.generateCertificate(inStream);
      }
    } catch (final CertificateException | IOException e) {
      throw new GemPkiRuntimeException("Konnte Zertifikat nicht lesen.", e);
    }
  }

  public static X509Certificate readX509(final Path path) {
    return readX509(Utils.readContent(path));
  }

  public static X509Certificate getX509FromP12(
      @NonNull final Path path, @NonNull final String password) {
    return Objects.requireNonNull(P12Reader.getContentFromP12(Utils.readContent(path), password))
        .getCertificate();
  }
}
