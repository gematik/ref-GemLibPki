/*
 * Copyright 2023 gematik GmbH
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
 */

package de.gematik.pki.gemlibpki.validators;

import de.gematik.pki.gemlibpki.certificate.CertificateProfile;
import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import java.security.cert.X509Certificate;
import java.util.Set;
import java.util.TreeSet;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x509.Extension;

@Slf4j
@RequiredArgsConstructor
public class CriticalExtensionsValidator implements CertificateProfileValidator {

  @NonNull private final String productType;

  /** AFO GS-A_4661-01 (RFC5280#4.2) */
  @Override
  public void validateCertificate(
      @NonNull final X509Certificate x509EeCert, @NonNull final CertificateProfile certificateProfile)
      throws GemPkiException {

    final Set<String> certCriticalExtensions = x509EeCert.getCriticalExtensionOIDs();

    // NOTE: as specified in gemSpec_PKI 2.15.0 for all certificate profiles in Kapitel 5
    // X.509-Zertifikate

    final Set<String> expectedCriticalExtensions =
        Set.of(Extension.basicConstraints.getId(), Extension.keyUsage.getId());

    if (!expectedCriticalExtensions.equals(certCriticalExtensions)) {
      log.error(
          "Detected unknown / missing critical extensions in certificate {} vs expected {}",
          new TreeSet<>(certCriticalExtensions),
          new TreeSet<>(expectedCriticalExtensions));
      throw new GemPkiException(productType, ErrorCode.CUSTOM_CERTIFICATE_EXCEPTION);
    }
  }
}
