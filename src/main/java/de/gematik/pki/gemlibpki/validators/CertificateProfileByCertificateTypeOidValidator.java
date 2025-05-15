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

package de.gematik.pki.gemlibpki.validators;

import static de.gematik.pki.gemlibpki.certificate.CertificateProfile.CERT_PROFILE_C_TSL_SIG;

import de.gematik.pki.gemlibpki.certificate.CertificateProfile;
import de.gematik.pki.gemlibpki.certificate.CertificateType;
import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import java.security.cert.X509Certificate;
import java.util.Set;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
public class CertificateProfileByCertificateTypeOidValidator
    implements CertificateProfileValidator {

  @NonNull private final String productType;

  /**
   * Check given list of certificate policy type oid(s) contains type oid from parameterized
   * certificate profile {@link CertificateProfile}.
   *
   * @throws GemPkiException if the certificate has a wong cert type
   */
  @Override
  public void validateCertificate(
      @NonNull final X509Certificate x509EeCert,
      @NonNull final CertificateProfile certificateProfile)
      throws GemPkiException {
    if (certificateProfile.equals(CERT_PROFILE_C_TSL_SIG)) {
      return;
    }
    final Set<String> certificatePolicyOidList = getCertificatePolicyOids(x509EeCert, productType);

    if (certificateProfile.getCertificateType().equals(CertificateType.CERT_TYPE_ANY)) {
      log.info(
          "Skipping check of CertificateTypeOid, because of user request. CertProfile used: {}",
          certificateProfile.name());
      return;
    }

    if (!certificatePolicyOidList.contains(certificateProfile.getCertificateType().getOid())) {
      log.debug("ZertifikatsTypOids im Zertifikat: {}", certificatePolicyOidList);
      log.debug(
          "Erwartete ZertifikatsTypOid: {}", certificateProfile.getCertificateType().getOid());
      throw new GemPkiException(productType, ErrorCode.SE_1018_CERT_TYPE_MISMATCH);
    }
  }
}
