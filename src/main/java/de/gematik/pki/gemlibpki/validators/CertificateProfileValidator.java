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

import de.gematik.pki.gemlibpki.certificate.CertificateProfile;
import de.gematik.pki.gemlibpki.certificate.Policies;
import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Set;
import lombok.NonNull;

public interface CertificateProfileValidator {

  void validateCertificate(
      @NonNull X509Certificate x509EeCert, @NonNull CertificateProfile certificateProfile)
      throws GemPkiException;

  /**
   * Get policy oids to given end-entity certificate. 1.Test: exists policy extension oid identifier
   * at all (implizit over IllegalArgumentException). 2.Test: extract value from policy extension
   * oid.
   *
   * @param x509EeCert end-entity certificate
   * @return Set<String> policy oids from end-entity certificate
   * @throws GemPkiException if the certificate has no cert type
   */
  default Set<String> getCertificatePolicyOids(
      final X509Certificate x509EeCert, final String productType) throws GemPkiException {
    try {
      final Policies policies = new Policies(x509EeCert);
      if (policies.getPolicyOids().isEmpty()) {
        throw new GemPkiException(productType, ErrorCode.SE_1033_CERT_TYPE_INFO_MISSING);
      }
      return policies.getPolicyOids();
    } catch (final IllegalArgumentException e) {
      throw new GemPkiException(productType, ErrorCode.SE_1033_CERT_TYPE_INFO_MISSING);
    } catch (final IOException e) {
      throw new GemPkiException(productType, ErrorCode.TE_1019_CERT_READ_ERROR);
    }
  }
}
