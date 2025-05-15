/*
 * Copyright (Date see Readme), gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */

package de.gematik.pki.gemlibpki.utils;

import static de.gematik.pki.gemlibpki.utils.GemLibPkiUtils.setBouncyCastleProvider;

import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
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

  static {
    setBouncyCastleProvider();
  }

  /**
   * Reads X.509 from byte[]
   *
   * @param bytes byte[] representation of X.509 certificate
   * @return X509Certificate
   */
  public static X509Certificate readX509(final byte[] bytes) {
    try {
      final CertificateFactory fact = CertificateFactory.getInstance("X.509");
      try (final ByteArrayInputStream inStream = new ByteArrayInputStream(bytes)) {
        return (X509Certificate) fact.generateCertificate(inStream);
      }
    } catch (final CertificateException | IOException e) {
      throw new GemPkiRuntimeException("Konnte Zertifikat nicht lesen.", e);
    }
  }

  /**
   * Reads X.509 from byte[]
   *
   * @param productType name of the product (used for specification persistent error logging)
   * @param bytes byte[] representation of X.509 certificate
   * @return {@link X509Certificate} extracted from byte[]
   * @throws GemPkiException when reading X.509 failed (Error Code
   *     TE_1002_TSL_CERT_EXTRACTION_ERROR)
   */
  public static X509Certificate readX509(final String productType, final byte[] bytes)
      throws GemPkiException {
    try {
      return readX509(bytes);
    } catch (final GemPkiRuntimeException e) {
      throw new GemPkiException(productType, ErrorCode.TE_1002_TSL_CERT_EXTRACTION_ERROR, e);
    }
  }

  /**
   * Reads X.509 from the path
   *
   * @param path the local file path of X.509 certificate
   * @return X509Certificate
   */
  public static X509Certificate readX509(@NonNull final Path path) {
    return readX509(GemLibPkiUtils.readContent(path));
  }

  /**
   * Reads X.509 from the P12 located under the path
   *
   * @param path the local file path of P12
   * @return X509Certificate
   */
  public static X509Certificate getX509FromP12(
      @NonNull final Path path, @NonNull final String password) {
    return Objects.requireNonNull(
            P12Reader.getContentFromP12(GemLibPkiUtils.readContent(path), password))
        .getCertificate();
  }
}
