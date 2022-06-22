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

import static de.gematik.pki.gemlibpki.TestConstants.FILE_NAME_TSL_DEFAULT;
import static de.gematik.pki.gemlibpki.TestConstants.LOCAL_SSP_DIR;
import static de.gematik.pki.gemlibpki.TestConstants.OCSP_HOST;
import static de.gematik.pki.gemlibpki.TestConstants.PRODUCT_TYPE;
import static de.gematik.pki.gemlibpki.utils.TestUtils.configureOcspResponderMockForOcspRequest;
import static de.gematik.pki.gemlibpki.utils.TestUtils.overwriteSspUrls;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.gemlibpki.common.OcspResponderMock;
import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.tsl.TucPki001Verifier.TucPki001VerifierBuilder;
import de.gematik.pki.gemlibpki.utils.P12Reader;
import de.gematik.pki.gemlibpki.utils.ResourceReader;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class TucPki001VerifierTest {

  private static List<TspService> tspServicesInTruststore;
  private static TrustStatusListType newTslToCheck;

  @BeforeAll
  static void start() {
    tspServicesInTruststore =
        new TslInformationProvider(
                TslReader.getTsl(ResourceReader.getFilePathFromResources(FILE_NAME_TSL_DEFAULT))
                    .orElseThrow())
            .getTspServices();
    newTslToCheck =
        TslReader.getTsl(ResourceReader.getFilePathFromResources(FILE_NAME_TSL_DEFAULT))
            .orElseThrow();
  }

  @Test
  void verifyPerformTucPki001ChecksValid() {
    final OcspResponderMock ocspResponderMock = new OcspResponderMock(LOCAL_SSP_DIR, OCSP_HOST);
    final X509Certificate tslSigner =
        P12Reader.getContentFromP12(
                Path.of(
                    "src/test/resources/certificates/GEM.TSL-CA8/TSL-Signing-Unit-8-TEST-ONLY.p12"),
                "00")
            .getCertificate();
    configureOcspResponderMockForOcspRequest(tslSigner, ocspResponderMock);
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
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage("OCSP senden/empfangen fehlgeschlagen.");
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
