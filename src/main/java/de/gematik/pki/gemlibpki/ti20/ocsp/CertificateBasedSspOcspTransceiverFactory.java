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

package de.gematik.pki.gemlibpki.ti20.ocsp;

import de.gematik.pki.gemlibpki.commons.error.ErrorCode;
import de.gematik.pki.gemlibpki.commons.exception.GemPkiException;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspTransceiver;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspTransceiverFactory;
import de.gematik.pki.gemlibpki.commons.tsl.TspInformationProvider;
import de.gematik.pki.gemlibpki.commons.tsl.TspService;
import de.gematik.pki.gemlibpki.commons.tsl.TspServiceSubset;
import de.gematik.pki.gemlibpki.ti20.certificate.AuthorityInformationAccessExtension;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;
import lombok.NonNull;

public class CertificateBasedSspOcspTransceiverFactory implements OcspTransceiverFactory {

  private final String productType;
  private final List<TspService> tspServiceList;
  private final int timeoutSeconds;
  private final boolean tolerateOcspFailure;

  public CertificateBasedSspOcspTransceiverFactory(
      @NonNull final String productType,
      @NonNull final List<TspService> tspServiceList,
      final int timeoutSeconds,
      final boolean tolerateOcspFailure) {
    this.productType = productType;
    this.tspServiceList = tspServiceList;
    this.timeoutSeconds = timeoutSeconds;
    this.tolerateOcspFailure = tolerateOcspFailure;
  }

  @Override
  public OcspTransceiver create(final X509Certificate eeCert) throws GemPkiException {

    final TspServiceSubset subset =
        new TspInformationProvider(tspServiceList, productType).getIssuerTspServiceSubset(eeCert);

    final String ssp;
    try {
      ssp = new AuthorityInformationAccessExtension(eeCert).getSsp();
    } catch (final IOException e) {
      throw new GemPkiException(
          ErrorCode.TE_1026_SERVICESUPPLYPOINT_MISSING,
          "AuthorityInformationAccessExtension empty",
          e);
    }

    return OcspTransceiver.builder()
        .productType(productType)
        .x509EeCert(eeCert)
        .x509IssuerCert(subset.getX509IssuerCert())
        .ssp(ssp)
        .ocspTimeoutSeconds(timeoutSeconds)
        .tolerateOcspFailure(tolerateOcspFailure)
        .build();
  }
}
