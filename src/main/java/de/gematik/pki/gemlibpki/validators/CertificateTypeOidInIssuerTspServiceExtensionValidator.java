/*
 * Copyright 2025, gematik GmbH
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
 * ******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */

package de.gematik.pki.gemlibpki.validators;

import static de.gematik.pki.gemlibpki.certificate.CertificateProfile.CERT_PROFILE_C_TSL_SIG;

import de.gematik.pki.gemlibpki.certificate.CertificateProfile;
import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.tsl.TspServiceSubset;
import eu.europa.esig.trustedlist.jaxb.tsl.ExtensionType;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.w3c.dom.Node;

@Slf4j
@RequiredArgsConstructor
public class CertificateTypeOidInIssuerTspServiceExtensionValidator
    implements CertificateProfileValidator {

  @NonNull private final String productType;
  @NonNull private final TspServiceSubset tspServiceSubset;

  /**
   * Verify that list of extension oid(s) from issuer TspService contains at least one oid of given
   * certificate type oid list.
   *
   * @throws GemPkiException if the certificate issuer is not allowed to issue this cert type
   */
  @Override
  public void validateCertificate(
      @NonNull final X509Certificate x509EeCert,
      @NonNull final CertificateProfile certificateProfile)
      throws GemPkiException {
    if (certificateProfile.equals(CERT_PROFILE_C_TSL_SIG)) {
      return;
    }
    final Set<String> certificateTypeOidList = getCertificatePolicyOids(x509EeCert, productType);

    log.debug(
        "Prüfe CA Autorisierung für die Herausgabe des Zertifikatstyps {} ",
        certificateProfile.getCertificateType().getOidReference());
    for (final ExtensionType extensionType : tspServiceSubset.getExtensions()) {
      final List<Object> content = extensionType.getContent();
      for (final Object object : content) {
        if (object instanceof final Node node) {
          final Node firstChild = node.getFirstChild();
          if (certificateTypeOidList.contains(firstChild.getNodeValue().trim())) {
            return;
          }
        }
      }
    }
    throw new GemPkiException(productType, ErrorCode.SE_1061_CERT_TYPE_CA_NOT_AUTHORIZED);
  }
}
