/*
 * Copyright (Change Date see Readme), gematik GmbH
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

package de.gematik.pki.gemlibpki.validators;

import de.gematik.pki.gemlibpki.certificate.CertificateProfile;
import de.gematik.pki.gemlibpki.certificate.KeyUsage;
import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import java.security.cert.X509Certificate;
import java.util.List;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
public class KeyUsageValidator implements CertificateProfileValidator {

  @NonNull private final String productType;

  /**
   * Verify that all intended KeyUsage bit(s) of certificate profile {@link CertificateProfile}
   * match against KeyUsage(s) of parameterized end-entity certificate and that the KeyUsages
   * extension in the certificate is present
   *
   * @throws GemPkiException if the certificate has a wrong key usage
   */
  @Override
  public void validateCertificate(
      @NonNull final X509Certificate x509EeCert,
      @NonNull final CertificateProfile certificateProfile)
      throws GemPkiException {

    final boolean[] certKeyUsage = x509EeCert.getKeyUsage();
    if (certKeyUsage == null) {
      log.error("KeyUsage extension im Zertifikat nicht vorhanden.");
      throw new GemPkiException(productType, ErrorCode.SE_1016_WRONG_KEYUSAGE);
    }

    final List<KeyUsage> intendedKeyUsageList =
        getIntendedKeyUsagesFromCertificateProfile(certificateProfile);
    if (intendedKeyUsageList.isEmpty()) {
      log.info(
          "Skipping check of KeyUsage, because of user request. CertProfile used: {}",
          certificateProfile.name());
      return;
    }

    int nrBitsEe = 0;

    for (final boolean bit : certKeyUsage) {
      if (bit) {
        nrBitsEe++;
      }
    }
    if (nrBitsEe != intendedKeyUsageList.size()) {
      throw new GemPkiException(productType, ErrorCode.SE_1016_WRONG_KEYUSAGE);
    }
    for (final KeyUsage keyUsage : intendedKeyUsageList) {
      if (!certKeyUsage[keyUsage.getBit()]) {
        throw new GemPkiException(productType, ErrorCode.SE_1016_WRONG_KEYUSAGE);
      }
    }
  }

  /**
   * Get list of KeyUsage(s) to the parameterized certificate profile {@link CertificateProfile}.
   *
   * @param certificateProfile The certificate profile
   * @return List with keyUsage(s)
   */
  private static List<KeyUsage> getIntendedKeyUsagesFromCertificateProfile(
      final CertificateProfile certificateProfile) {
    return CertificateProfile.valueOf(certificateProfile.name()).getKeyUsages();
  }
}
