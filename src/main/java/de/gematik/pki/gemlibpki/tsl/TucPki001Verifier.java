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

package de.gematik.pki.gemlibpki.tsl;

import de.gematik.pki.gemlibpki.certificate.CertificateProfile;
import de.gematik.pki.gemlibpki.certificate.TucPki018Verifier;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.ocsp.OcspConstants;
import de.gematik.pki.gemlibpki.ocsp.OcspRespCache;
import de.gematik.pki.gemlibpki.utils.CertReader;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import eu.europa.esig.xmldsig.jaxb.X509DataType;
import java.security.cert.X509Certificate;
import java.util.List;
import javax.xml.bind.JAXBElement;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Entry point to access a verification of TSLs regarding standard process called TucPki001. This
 * class works with parameterized variables (defined by builder pattern) and with given variables
 * provided by runtime (method parameters).
 *
 * <p>Member "currentTrustedServices" holds the services of the current trust store (the established
 * trust space from former successful tsl parsings)
 */
@Slf4j
@RequiredArgsConstructor(access = AccessLevel.PROTECTED)
@Builder
public class TucPki001Verifier {

  @NonNull protected final String productType;
  @NonNull protected final List<TspService> currentTrustedServices;
  @NonNull protected final TrustStatusListType tslToCheck;
  @Builder.Default protected final boolean withOcspCheck = true;
  protected final OcspRespCache ocspRespCache;

  @Builder.Default
  protected final int ocspTimeoutSeconds = OcspConstants.DEFAULT_OCSP_TIMEOUT_SECONDS;

  @Builder.Default protected final boolean tolerateOcspFailure = false;

  /**
   * Performs TUC_PKI_001 checks (TSL verification)
   *
   * @throws GemPkiException thrown when TSL is not conform to gemSpec_PKI
   */
  public void performTucPki001Checks() throws GemPkiException {
    log.debug("TUC_PKI_001 Checks...");
    final X509Certificate tslSigner =
        CertReader.readX509(
            (byte[])
                tslToCheck.getSignature().getKeyInfo().getContent().stream()
                    .filter(JAXBElement.class::isInstance)
                    .map(JAXBElement.class::cast)
                    .map(JAXBElement::getValue)
                    .filter(X509DataType.class::isInstance)
                    .map(X509DataType.class::cast)
                    .map(X509DataType::getX509IssuerSerialOrX509SKIOrX509SubjectName)
                    .flatMap(List::stream)
                    .filter(JAXBElement.class::isInstance)
                    .map(JAXBElement.class::cast)
                    .map(JAXBElement::getValue)
                    .findFirst()
                    .orElseThrow());

    final TucPki018Verifier certVerifier =
        TucPki018Verifier.builder()
            .productType(productType)
            .ocspRespCache(ocspRespCache)
            .tspServiceList(currentTrustedServices)
            .certificateProfiles(List.of(CertificateProfile.CERT_PROFILE_C_TSL_SIG))
            .withOcspCheck(withOcspCheck)
            .ocspTimeoutSeconds(ocspTimeoutSeconds)
            .tolerateOcspFailure(tolerateOcspFailure)
            .build();

    certVerifier.performTucPki18Checks(tslSigner);
  }
}
