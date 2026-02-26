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

package de.gematik.pki.gemlibpki.ti20.certificate;

import static de.gematik.pki.gemlibpki.commons.TestConstants.OCSP_HOST;
import static de.gematik.pki.gemlibpki.commons.TestConstants.PRODUCT_TYPE;
import static de.gematik.pki.gemlibpki.commons.TestConstants.TI20_VALID_X509_EE_CERT_SMCB;
import static de.gematik.pki.gemlibpki.commons.TestConstants.VALID_X509_EE_CERT_SMCB;
import static de.gematik.pki.gemlibpki.commons.certificate.CertificateProfile.CERT_PROFILE_C_HCI_AUT_ECC;
import static de.gematik.pki.gemlibpki.commons.utils.TestUtils.overwriteSspUrls;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.gemlibpki.commons.certificate.CertificateProfile;
import de.gematik.pki.gemlibpki.commons.certificate.TucPki018Verifier;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspRespCache;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspResponderMock;
import de.gematik.pki.gemlibpki.commons.tsl.TspService;
import de.gematik.pki.gemlibpki.commons.utils.TestUtils;
import de.gematik.pki.gemlibpki.ti20.ocsp.CertificateBasedSspOcspTransceiverFactory;
import java.net.URI;
import java.util.List;
import lombok.SneakyThrows;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class TucPki018VerifierIT {

  private static final List<CertificateProfile> certificateProfiles =
      List.of(CERT_PROFILE_C_HCI_AUT_ECC);
  private static OcspResponderMock ocspResponderMock;
  private static final int OCSP_GRACE_PERIOD_30_SECONDS = 30;
  static final int TIMEOUT = 5;
  static final boolean TOLERATE_FAILURE = false;

  private TucPki018Verifier tucPki018Verifier;
  private OcspRespCache ocspRespCache;

  @SneakyThrows
  @BeforeAll
  void setup() {
    final String ssp =
        new AuthorityInformationAccessExtension(TI20_VALID_X509_EE_CERT_SMCB).getSsp();
    final URI sspUri = URI.create(ssp);
    ocspResponderMock =
        OcspResponderMock.createAndStart(sspUri.getPath(), OCSP_HOST, sspUri.getPort());
  }

  @AfterAll
  void tearDown() {
    ocspResponderMock.stop();
  }

  @BeforeEach
  void init() {
    ocspRespCache = new OcspRespCache(OCSP_GRACE_PERIOD_30_SECONDS);
    tucPki018Verifier = buildTucPki018Verifier(certificateProfiles);
  }

  private TucPki018Verifier buildTucPki018Verifier(
      final List<CertificateProfile> certificateProfiles) {

    final List<TspService> tspServiceList = TestUtils.getDefaultTspServiceList();
    overwriteSspUrls(tspServiceList, ocspResponderMock.getSspUrl());
    final CertificateBasedSspOcspTransceiverFactory ocspTransceiverFactory =
        new CertificateBasedSspOcspTransceiverFactory(
            PRODUCT_TYPE, tspServiceList, TIMEOUT, TOLERATE_FAILURE);

    return TucPki018Verifier.builder()
        .productType(PRODUCT_TYPE)
        .tspServiceList(tspServiceList)
        .certificateProfiles(certificateProfiles)
        .ocspRespCache(ocspRespCache)
        .ocspTimeToleranceProducedAtPastMilliseconds(OCSP_GRACE_PERIOD_30_SECONDS * 1000)
        .ocspTransceiverFactory(ocspTransceiverFactory)
        .build();
  }

  /**
   * Take the real OCSP responder of eHealth CA. No OcspResponder mock. This test is more of an
   * integration test, but it is good to have it to check that the verifier works with real OCSP
   * responders and not only with mocks.
   */
  @Test
  void verifyPerformTucPki18ChecksValid_OcspResponderEhealthCa() {
    assertDoesNotThrow(() -> tucPki018Verifier.performTucPki018Checks(VALID_X509_EE_CERT_SMCB));
  }
}
