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

package de.gematik.pki.gemlibpki.ocsp;

import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.SingleResp;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class OcspUtils {

  public static final String OCSP_RESPONSE_ERROR = "OCSP Response Auswertung fehlgeschlagen.";

  /**
   * @param ocspResponse OCSP response
   * @return basic OCSP response if available; otherwise {@link GemPkiRuntimeException} is thrown
   */
  public static BasicOCSPResp getBasicOcspResp(@NonNull final OCSPResp ocspResponse) {
    try {
      final BasicOCSPResp basicOcspResp = (BasicOCSPResp) ocspResponse.getResponseObject();
      if (basicOcspResp == null) {
        throw new GemPkiRuntimeException("Keine OCSP Response erhalten.");
      }
      return basicOcspResp;
    } catch (final OCSPException e) {
      throw new GemPkiRuntimeException(OCSP_RESPONSE_ERROR, e);
    }
  }

  /**
   * @param ocspReq OCSP request
   * @return request, if available und distinct; otherwise {@link GemPkiRuntimeException} is thrown
   */
  public static Req getFirstSingleReq(@NonNull final OCSPReq ocspReq) {
    final Req[] singleReqs = ocspReq.getRequestList();

    if (singleReqs.length != 1) {
      throw new GemPkiRuntimeException(
          "Mehr als einen OCSP Request erhalten: " + singleReqs.length);
    }

    return singleReqs[0];
  }

  /**
   * @param ocspResponse OCSP response
   * @return single response, if available und distinct; otherwise {@link GemPkiRuntimeException} is
   *     thrown
   */
  public static SingleResp getFirstSingleResp(@NonNull final OCSPResp ocspResponse) {

    final BasicOCSPResp basicOcspResp = getBasicOcspResp(ocspResponse);

    final SingleResp[] singleResps = basicOcspResp.getResponses();

    if (singleResps.length != 1) {
      throw new GemPkiRuntimeException(
          "Nicht genau eine OCSP Response erhalten, sondern: " + singleResps.length);
    }
    return singleResps[0];
  }
}
