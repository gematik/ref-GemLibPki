/*
 * Copyright 2023 gematik GmbH
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
 */

package de.gematik.pki.gemlibpki.ocsp;

import static de.gematik.pki.gemlibpki.TestConstants.VALID_ISSUER_CERT_SMCB;
import static de.gematik.pki.gemlibpki.TestConstants.VALID_X509_EE_CERT_SMCB;
import static de.gematik.pki.gemlibpki.ocsp.OcspUtils.OCSP_RESPONSE_ERROR;
import static de.gematik.pki.gemlibpki.utils.TestUtils.assertNonNullParameter;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

class OcspUtilsTest {

  @Test
  void nonNullTests() {
    assertNonNullParameter(() -> OcspUtils.getBasicOcspResp(null), "ocspResponse");

    assertNonNullParameter(() -> OcspUtils.getFirstSingleResp(null), "ocspResponse");

    assertNonNullParameter(() -> OcspUtils.getFirstSingleReq(null), "ocspReq");
  }

  OCSPResp getOcspResp() {

    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);
    return OcspResponseGenerator.builder()
        .signer(OcspTestConstants.getOcspSignerEcc())
        .build()
        .generate(ocspReq, VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);
  }

  @Test
  void testGetBasicOcspRespNull() throws OCSPException {
    final OCSPResp ocspResp = getOcspResp();

    final OCSPResp ocspRespMock = Mockito.spy(ocspResp);
    Mockito.when(ocspRespMock.getResponseObject()).thenReturn(null);

    assertThatThrownBy(() -> OcspUtils.getBasicOcspResp(ocspRespMock))
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage("Keine OCSP Response erhalten.");
  }

  @Test
  void testGetBasicOcspRespOcspException() throws OCSPException {
    final OCSPResp ocspResp = getOcspResp();

    final OCSPResp ocspRespMock = Mockito.spy(ocspResp);
    Mockito.when(ocspRespMock.getResponseObject()).thenThrow(new OCSPException("ocspException"));

    assertThatThrownBy(() -> OcspUtils.getBasicOcspResp(ocspRespMock))
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage(OCSP_RESPONSE_ERROR);
  }

  @Test
  void testGetFirstSingleResp() throws OCSPException {
    final OCSPResp ocspResp = getOcspResp();
    final OCSPResp ocspRespMock = Mockito.spy(ocspResp);

    final BasicOCSPResp basicOcspResp = (BasicOCSPResp) ocspResp.getResponseObject();
    final BasicOCSPResp basicOcspRespMock = Mockito.spy(basicOcspResp);

    final SingleResp singleResp = basicOcspResp.getResponses()[0];

    Mockito.when(ocspRespMock.getResponseObject()).thenReturn(basicOcspRespMock);
    Mockito.when(basicOcspRespMock.getResponses())
        .thenReturn(new SingleResp[] {singleResp, singleResp});

    assertThatThrownBy(() -> OcspUtils.getFirstSingleResp(ocspRespMock))
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage("Nicht genau eine OCSP Response erhalten, sondern: 2");
  }

  @Test
  void testGetFirstSingleReq() {

    final OCSPReq ocspReq =
        OcspRequestGenerator.generateSingleOcspRequest(
            VALID_X509_EE_CERT_SMCB, VALID_ISSUER_CERT_SMCB);
    final OCSPReq ocspReqMock = Mockito.spy(ocspReq);

    final Req req = ocspReq.getRequestList()[0];

    Mockito.when(ocspReqMock.getRequestList()).thenReturn(new Req[] {req, req});

    assertThatThrownBy(() -> OcspUtils.getFirstSingleReq(ocspReqMock))
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage("Mehr als eine OCSP Request erhalten: 2");
  }
}
