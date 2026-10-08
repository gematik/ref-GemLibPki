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

package de.gematik.pki.gemlibpki.commons.tsl;

import static de.gematik.pki.gemlibpki.commons.utils.CertReader.readX509;

import de.gematik.pki.gemlibpki.commons.utils.GemLibPkiUtils;
import eu.europa.esig.trustedlist.jaxb.tsl.DigitalIdentityType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceType;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Objects;
import java.util.Optional;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/** Class to encapsulate package eu.europa.esig */
@SuppressWarnings("ClassCanBeRecord")
@RequiredArgsConstructor
@Getter
public class TspService {

  private final TSPServiceType tspServiceType;

  public X509Certificate getFirstX509Certificate() {
    return readX509(
        tspServiceType
            .getServiceInformation()
            .getServiceDigitalIdentity()
            .getDigitalId()
            .getFirst()
            .getX509Certificate());
  }

  public boolean hasServiceTypeIdentifier(@NonNull final String serviceTypeIdentifier) {
    return serviceTypeIdentifier.equals(
        tspServiceType.getServiceInformation().getServiceTypeIdentifier());
  }

  public boolean isOcspService() {
    return hasServiceTypeIdentifier(TslConstants.STI_OCSP)
        || hasServiceTypeIdentifier(TslConstants.STI_OCSP_QC);
  }

  public boolean containsCertificate(@NonNull final X509Certificate certificate) {
    return getMatchingCertificate(certificate).isPresent();
  }

  public Optional<X509Certificate> getMatchingCertificate(
      @NonNull final X509Certificate certificate) {
    if (tspServiceType.getServiceInformation() == null
        || tspServiceType.getServiceInformation().getServiceDigitalIdentity() == null
        || tspServiceType.getServiceInformation().getServiceDigitalIdentity().getDigitalId()
            == null) {
      return Optional.empty();
    }

    final byte[] certificateHash =
        GemLibPkiUtils.calculateSha256(GemLibPkiUtils.certToBytes(certificate));

    return tspServiceType
        .getServiceInformation()
        .getServiceDigitalIdentity()
        .getDigitalId()
        .stream()
        .filter(Objects::nonNull)
        .map(DigitalIdentityType::getX509Certificate)
        .filter(Objects::nonNull)
        .filter(
            candidateCertificate ->
                MessageDigest.isEqual(
                    certificateHash, GemLibPkiUtils.calculateSha256(candidateCertificate)))
        .findFirst()
        .map(candidateCertificate -> readX509(candidateCertificate));
  }

  @Override
  public String toString() {
    return tspServiceType.getServiceInformation().getServiceName().getName().getFirst().getValue();
  }
}
