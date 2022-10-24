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

import static de.gematik.pki.gemlibpki.TestConstants.LOCAL_SSP_DIR;
import static de.gematik.pki.gemlibpki.TestConstants.OCSP_HOST;
import static de.gematik.pki.gemlibpki.TestConstants.PRODUCT_TYPE;
import static de.gematik.pki.gemlibpki.TestConstants.VALID_ISSUER_CERT_TSL_CA8;
import static de.gematik.pki.gemlibpki.utils.TestUtils.overwriteSspUrls;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.gemlibpki.common.OcspResponderMock;
import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.tsl.TucPki001Verifier.TucPki001VerifierBuilder;
import de.gematik.pki.gemlibpki.utils.TestUtils;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import eu.europa.esig.xmldsig.jaxb.X509DataType;
import java.security.cert.X509Certificate;
import java.util.List;
import javax.xml.bind.JAXBElement;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class TucPki001VerifierTest {

  private static List<TspService> tspServicesInTruststore;
  private static final TrustStatusListType newTslToCheck = TestUtils.getDefaultTsl();

  @BeforeAll
  static void start() {
    tspServicesInTruststore = TestUtils.getDefaultTspServiceList();
    overwriteSspUrls(tspServicesInTruststore, "invalidSsp");
  }

  @Test
  void verifyPerformTucPki001ChecksValid() {
    final OcspResponderMock ocspResponderMock = new OcspResponderMock(LOCAL_SSP_DIR, OCSP_HOST);
    final X509Certificate tslSigner =
        TestUtils.readP12("GEM.TSL-CA8/TSL-Signing-Unit-8-TEST-ONLY.p12").getCertificate();
    ocspResponderMock.configureForOcspRequest(tslSigner, VALID_ISSUER_CERT_TSL_CA8);
    overwriteSspUrls(tspServicesInTruststore, ocspResponderMock.getSspUrl());

    final TucPki001Verifier tucPki001Verifier =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(newTslToCheck)
            .currentTrustedServices(tspServicesInTruststore)
            .build();
    assertDoesNotThrow(tucPki001Verifier::performTucPki001Checks);
  }

  @Test
  void verifyGetTslSignerCertificateInvalidFindFirst() {

    final TrustStatusListType tslToCheck = TestUtils.getDefaultTsl();

    tslToCheck.getSignature().getKeyInfo().getContent().clear();

    final TucPki001Verifier tucPki001Verifier =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(tslToCheck)
            .currentTrustedServices(tspServicesInTruststore)
            .build();

    assertThatThrownBy(tucPki001Verifier::getTslSignerCertificate)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1002_TSL_CERT_EXTRACTION_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyGetTslSignerCertificateInvalidManyChanges() {

    final TrustStatusListType tslToCheck = TestUtils.getDefaultTsl();

    final List<JAXBElement> jaxbElements =
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
            .toList();

    final JAXBElement jaxbElement = jaxbElements.get(0);

    jaxbElement.setValue("invalidbytesX509Certificate".getBytes());

    final TucPki001Verifier tucPki001Verifier =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(tslToCheck)
            .currentTrustedServices(tspServicesInTruststore)
            .build();

    assertThatThrownBy(tucPki001Verifier::getTslSignerCertificate)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1002_TSL_CERT_EXTRACTION_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyGetTslSignerCertificateInvalidFewChanges() {

    final TrustStatusListType tslToCheck = TestUtils.getDefaultTsl();

    final List<JAXBElement> jaxbElements =
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
            .toList();

    final JAXBElement jaxbElement = jaxbElements.get(0);
    final byte[] bytes = (byte[]) jaxbElement.getValue();

    // change content
    for (int i = 0; i < 9; ++i) {
      bytes[i] = '*';
    }

    final TucPki001Verifier tucPki001Verifier =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(tslToCheck)
            .currentTrustedServices(tspServicesInTruststore)
            .build();

    assertThatThrownBy(tucPki001Verifier::getTslSignerCertificate)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1002_TSL_CERT_EXTRACTION_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyPerformTucPki001ChecksOcspDisabled() {
    final TucPki001Verifier tucPki001Verifier =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(newTslToCheck)
            .currentTrustedServices(tspServicesInTruststore)
            .withOcspCheck(false)
            .build();
    assertDoesNotThrow(tucPki001Verifier::performTucPki001Checks);
  }

  @Test
  void verifyPerformTucPki001ChecksWithoutOcspInvalid() {
    final TucPki001Verifier tucPki001Verifier =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(newTslToCheck)
            .currentTrustedServices(tspServicesInTruststore)
            .build();

    assertThatThrownBy(tucPki001Verifier::performTucPki001Checks)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR.getErrorMessage(PRODUCT_TYPE));
  }

  @Test
  void verifyNullChecks() {
    final TucPki001VerifierBuilder builder = TucPki001Verifier.builder();

    assertThatThrownBy(() -> builder.productType(null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("productType is marked non-null but is null");

    assertThatThrownBy(() -> builder.tslToCheck(null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("tslToCheck is marked non-null but is null");

    assertThatThrownBy(() -> builder.currentTrustedServices(null))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("currentTrustedServices is marked non-null but is null");
  }
}
