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

package de.gematik.pki.tsl;

import de.gematik.pki.error.ErrorCode;
import de.gematik.pki.exception.GemPkiException;
import de.gematik.pki.ocsp.OcspRespCache;
import de.gematik.pki.ocsp.OcspTransceiver;
import de.gematik.pki.utils.CertReader;
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
 * Entry point to access a verification of TSLs regarding standard process called TucPki001. This class works with parameterized variables (defined by builder
 * pattern) and with given variables provided by runtime (method parameters).
 * <p>
 * Member "currentTrustedServices" holds the services of the current trust store (the established trust space from former successful tsl parsings)
 */
@Slf4j
@RequiredArgsConstructor(access = AccessLevel.PROTECTED)
@Builder
public class TucPki001Verifier {

    @NonNull
    protected final String productType;
    @NonNull
    protected final List<TspService> currentTrustedServices;
    @NonNull
    protected final TrustStatusListType tslToCheck;
    @Builder.Default
    protected final boolean withOcspCheck = true; //NOSONAR
    protected final OcspRespCache ocspRespCache;

    public void performTucPki001Checks() throws GemPkiException {
        log.debug("TucPki001Checks...");
        final X509Certificate tslSigner = CertReader.readX509((byte[]) tslToCheck.getSignature().getKeyInfo().getContent().stream()
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
            .findFirst().orElseThrow());

        final TspServiceSubset tspServiceSubsetOfTrustAnchor = new TspInformationProvider(currentTrustedServices, productType).getTspServiceSubset(tslSigner);
        doOcspIfConfigured(tslSigner, tspServiceSubsetOfTrustAnchor);
    }

    protected void doOcspIfConfigured(final X509Certificate tslSigner, final TspServiceSubset tspServiceSubsetOfTrustAnchor) throws GemPkiException {
        if (withOcspCheck) {
            OcspTransceiver.builder()
                .productType(productType)
                .x509EeCert(tslSigner)
                .x509IssuerCert(tspServiceSubsetOfTrustAnchor.getX509IssuerCert())
                .ssp(tspServiceSubsetOfTrustAnchor.getServiceSupplyPoint())
                .build()
                .verifyOcspResponse(ocspRespCache);
        } else {
            log.warn(ErrorCode.SW_1039.getErrorMessage(productType));
        }
    }
}
