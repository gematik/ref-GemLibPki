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
import de.gematik.pki.gemlibpki.certificate.ExtendedKeyUsage;
import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.List;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
public class ExtendedKeyUsageValidator implements CertificateProfileValidator {

  @NonNull private final String productType;

  /**
   * Verify oid of intended ExtendedKeyUsage(s) from certificate profile {@link CertificateProfile}
   * must match with oid(s) from a parameterized end-entity certificate with respect to cardinality.
   *
   * @throws GemPkiException if certificate has a wrong key usage
   */
  @Override
  public void validateCertificate(
      @NonNull final X509Certificate x509EeCert,
      @NonNull final CertificateProfile certificateProfile)
      throws GemPkiException {

    final List<String> intendedExtendedKeyUsageOidList =
        getOidOfIntendedExtendedKeyUsagesFromCertificateProfile(certificateProfile);

    if (intendedExtendedKeyUsageOidList.isEmpty() || !certificateProfile.isFailOnMissingEku()) {
      log.info(
          "Skipping check of extendedKeyUsage, because of user request. CertProfile used: {}",
          certificateProfile.name());
      return;
    }

    final List<String> eeExtendedKeyUsagesOid = getExtendedKeyUsagesOid(x509EeCert);
    final List<String> filteredList =
        eeExtendedKeyUsagesOid.stream()
            .filter(
                eeOid ->
                    intendedExtendedKeyUsageOidList.stream()
                        .anyMatch(intOid -> intOid.equals(eeOid)))
            .toList();
    if (filteredList.isEmpty()
        || (eeExtendedKeyUsagesOid.size() != intendedExtendedKeyUsageOidList.size())) {
      log.debug("{}", ErrorCode.SE_1017_WRONG_EXTENDEDKEYUSAGE.getErrorMessage(productType));
      throw new GemPkiException(productType, ErrorCode.SE_1017_WRONG_EXTENDEDKEYUSAGE);
    }
  }

  private List<String> getExtendedKeyUsagesOid(final X509Certificate x509EeCert)
      throws GemPkiException {
    final List<String> eeExtendedKeyUsagesOid;
    try {
      eeExtendedKeyUsagesOid = x509EeCert.getExtendedKeyUsage();
    } catch (final CertificateParsingException e) {
      throw new GemPkiRuntimeException(
          "Fehler beim Lesen der ExtendedKeyUsages des Zertifikats: "
              + x509EeCert.getSubjectX500Principal().getName(),
          e);
    }

    if (eeExtendedKeyUsagesOid == null) {
      throw new GemPkiException(productType, ErrorCode.SE_1017_WRONG_EXTENDEDKEYUSAGE);
    }
    return eeExtendedKeyUsagesOid;
  }

  /**
   * Get list of oid(s) of ExtendedKeyUsage(s) to the parameterized profile.
   *
   * @param certificateProfile The certificate profile
   * @return List of oid(s) of ExtendedKeyUsages from certificate profile {@link CertificateProfile}
   */
  private static List<String> getOidOfIntendedExtendedKeyUsagesFromCertificateProfile(
      final CertificateProfile certificateProfile) {
    return CertificateProfile.valueOf(certificateProfile.name()).getExtKeyUsages().stream()
        .map(ExtendedKeyUsage::getOid)
        .toList();
  }
}
