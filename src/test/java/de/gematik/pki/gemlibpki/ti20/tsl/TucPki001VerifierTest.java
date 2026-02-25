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

import static de.gematik.pki.gemlibpki.commons.TestConstants.FILE_NAME_TSL_ECC_DEFAULT_SIGNER_SSP_LOCALHOST;
import static de.gematik.pki.gemlibpki.commons.TestConstants.OCSP_HOST;
import static de.gematik.pki.gemlibpki.commons.TestConstants.PRODUCT_TYPE;
import static de.gematik.pki.gemlibpki.commons.TestConstants.VALID_ISSUER_CERT_TSL_CA51;
import static de.gematik.pki.gemlibpki.commons.tsl.TslUtils.getFirstTslSignerCertificate;
import static de.gematik.pki.gemlibpki.commons.utils.TestUtils.overwriteSspUrls;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.gemlibpki.commons.error.ErrorCode;
import de.gematik.pki.gemlibpki.commons.exception.GemPkiException;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspResponderMock;
import de.gematik.pki.gemlibpki.commons.tsl.TslConverter;
import de.gematik.pki.gemlibpki.commons.tsl.TslInformationProvider;
import de.gematik.pki.gemlibpki.commons.tsl.TspService;
import de.gematik.pki.gemlibpki.commons.tsl.TucPki001Verifier;
import de.gematik.pki.gemlibpki.commons.utils.TestUtils;
import de.gematik.pki.gemlibpki.ti20.certificate.AuthorityInformationAccessExtension;
import de.gematik.pki.gemlibpki.ti20.ocsp.CertificateBasedSspOcspTransceiverFactory;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

class TucPki001VerifierTest {

  private static List<TspService> tspServicesInTruststore;
  static final int OCSP_TIMEOUT = 5;
  static final boolean OCSP_TOLERATE_FAILURE = false;

  @BeforeAll
  static void start() {
    final TrustStatusListType tslToCheckTslUnsigned = TestUtils.getDefaultTslUnsigned();
    tspServicesInTruststore = new TslInformationProvider(tslToCheckTslUnsigned).getTspServices();
    overwriteSspUrls(tspServicesInTruststore, "invalidSsp");
  }

  @Test
  void verifyPerformTucPki001ChecksValid_OcspResponderLocalhost() throws IOException {
    final Document tslSignerSspLocalhost =
        TestUtils.getTslAsDoc(FILE_NAME_TSL_ECC_DEFAULT_SIGNER_SSP_LOCALHOST);
    final byte[] tslBytes = TslConverter.docToBytes(tslSignerSspLocalhost);

    final TrustStatusListType tsltTslSignerSspLocalhost =
        TestUtils.getTslUnsigned(FILE_NAME_TSL_ECC_DEFAULT_SIGNER_SSP_LOCALHOST);
    final X509Certificate tslSigner = getFirstTslSignerCertificate(tsltTslSignerSspLocalhost);
    final String ssp = new AuthorityInformationAccessExtension(tslSigner).getSsp();
    final URI sspUri = URI.create(ssp);
    final OcspResponderMock ocspResponderMock =
        OcspResponderMock.createAndStart("/ocsp", OCSP_HOST, sspUri.getPort());
    ocspResponderMock.configureForOcspRequest(tslSigner, VALID_ISSUER_CERT_TSL_CA51);

    overwriteSspUrls(tspServicesInTruststore, "invalidated");

    final CertificateBasedSspOcspTransceiverFactory ocspTransceiverFactory =
        new CertificateBasedSspOcspTransceiverFactory(
            PRODUCT_TYPE, tspServicesInTruststore, OCSP_TIMEOUT, OCSP_TOLERATE_FAILURE);

    // With OcspTransceiverFactory the TucPki001Verifier has to use the SSP out of TSL signer
    // certificate.
    final TucPki001Verifier tucPki001VerifierOcspTransFactory =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(tslBytes)
            .currentTrustedServices(tspServicesInTruststore)
            .currentTslId("dummyTslId")
            .currentTslSeqNr(BigInteger.ZERO)
            .ocspTransceiverFactory(ocspTransceiverFactory)
            .build();
    assertDoesNotThrow(tucPki001VerifierOcspTransFactory::performTucPki001Checks);

    // Without OcspTransceiverFactory the TucPki001Verifier has to use the SSP out of the TSL and
    // this entry is invalidated.
    final TucPki001Verifier tucPki001VerifierDefault =
        TucPki001Verifier.builder()
            .productType(PRODUCT_TYPE)
            .tslToCheck(tslBytes)
            .currentTrustedServices(tspServicesInTruststore)
            .currentTslId("dummyTslId")
            .currentTslSeqNr(BigInteger.ZERO)
            .build();
    assertThatThrownBy(tucPki001VerifierDefault::performTucPki001Checks)
        .isInstanceOf(GemPkiException.class)
        .hasMessage(ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR.getErrorMessage(PRODUCT_TYPE));

    ocspResponderMock.stop();
  }
}
