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

package de.gematik.pki.gemlibpki.ti20.tsl;

import static de.gematik.pki.gemlibpki.commons.TestConstants.PRODUCT_TYPE;
import static de.gematik.pki.gemlibpki.commons.utils.TestUtils.overwriteSspUrls;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.gemlibpki.commons.tsl.TslConverter;
import de.gematik.pki.gemlibpki.commons.tsl.TslInformationProvider;
import de.gematik.pki.gemlibpki.commons.tsl.TspService;
import de.gematik.pki.gemlibpki.commons.tsl.TucPki001Verifier;
import de.gematik.pki.gemlibpki.commons.utils.TestUtils;
import de.gematik.pki.gemlibpki.ti20.ocsp.CertificateBasedSspOcspTransceiverFactory;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.math.BigInteger;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

class TucPki001VerifierIT {

  private static List<TspService> tspServicesInTruststore;
  private static byte[] tslToCheck;
  static final int OCSP_TIMEOUT = 5;
  static final boolean OCSP_TOLERATE_FAILURE = false;

  @BeforeAll
  static void start() {
    final TrustStatusListType tslToCheckTslUnsigned = TestUtils.getDefaultTslUnsigned();
    final Document tslToCheckDoc = TestUtils.getDefaultTslAsDoc();
    tslToCheck = TslConverter.docToBytes(tslToCheckDoc);
    tspServicesInTruststore = new TslInformationProvider(tslToCheckTslUnsigned).getTspServices();
    overwriteSspUrls(tspServicesInTruststore, "invalidSsp");
  }

  @Test
  void verifyPerformTucPki001ChecksValid_OcspResponderEHealthCa() {
    // With OcspTransceiverFactory the TucPki001Verifier must not use the SSP out of the TSL
    // therefore this entry is invalidated.
    overwriteSspUrls(tspServicesInTruststore, "invalidated");

    final CertificateBasedSspOcspTransceiverFactory ocspTransceiverFactory =
        new CertificateBasedSspOcspTransceiverFactory(
            PRODUCT_TYPE, tspServicesInTruststore, OCSP_TIMEOUT, OCSP_TOLERATE_FAILURE);

    final TucPki001Verifier tucPki001Verifier =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(tslToCheck)
            .currentTrustedServices(tspServicesInTruststore)
            .currentTslId("dummyTslId")
            .currentTslSeqNr(BigInteger.ZERO)
            .ocspTransceiverFactory(ocspTransceiverFactory)
            .build();
    assertDoesNotThrow(tucPki001Verifier::performTucPki001Checks);
  }
}
