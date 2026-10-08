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

package de.gematik.pki.gemlibpki.ti10.ocsp;

import de.gematik.pki.gemlibpki.commons.exception.GemPkiException;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspSspSupport;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspTransceiver;
import de.gematik.pki.gemlibpki.commons.ocsp.OcspTransceiverFactory;
import de.gematik.pki.gemlibpki.commons.tsl.TslConstants;
import de.gematik.pki.gemlibpki.commons.tsl.TspService;
import eu.europa.esig.trustedlist.jaxb.tsl.AdditionalServiceInformationType;
import eu.europa.esig.trustedlist.jaxb.tsl.ExtensionType;
import java.security.cert.X509Certificate;
import java.util.List;
import lombok.NonNull;

public class TucPki030OcspTransceiverFactory implements OcspTransceiverFactory {

  private final String productType;
  private final X509Certificate x509IssuerCert;
  private final List<TspService> tspServiceListTsl;
  private final int timeoutSeconds;
  private final boolean tolerateOcspFailure;

  public TucPki030OcspTransceiverFactory(
      final String productType,
      final X509Certificate x509IssuerCert,
      final List<TspService> tspServiceListTsl,
      final int timeoutSeconds,
      final boolean tolerateOcspFailure) {
    this.productType = productType;
    this.x509IssuerCert = x509IssuerCert;
    this.tspServiceListTsl = tspServiceListTsl;
    this.timeoutSeconds = timeoutSeconds;
    this.tolerateOcspFailure = tolerateOcspFailure;
  }

  @Override
  public OcspTransceiver create(final X509Certificate eeCert) throws GemPkiException {
    return OcspTransceiver.builder()
        .productType(productType)
        .x509EeCert(eeCert)
        .x509IssuerCert(x509IssuerCert)
        .ssp(determineOcspSsp(eeCert))
        .ocspTimeoutSeconds(timeoutSeconds)
        .tolerateOcspFailure(tolerateOcspFailure)
        .build();
  }

  protected String determineOcspSsp(@NonNull final X509Certificate x509EeCert)
      throws GemPkiException {
    final String aiaOcspUrl = OcspSspSupport.extractAiaOcspUrl(productType, x509EeCert);
    return findTslOcspUrlOverride(aiaOcspUrl);
  }

  protected String findTslOcspUrlOverride(final String aiaOcspUrl) {
    final List<TspService> bNetzAVlServices = filterBNetzAVlServices();
    final List<AdditionalServiceInformationType> asiList =
        extractAllAdditionalServiceInformation(bNetzAVlServices);
    return findMatchingTslOcspUrl(asiList, aiaOcspUrl);
  }

  protected List<TspService> filterBNetzAVlServices() {
    return tspServiceListTsl.stream().filter(this::isBNetzAVlService).toList();
  }

  protected List<AdditionalServiceInformationType> extractAllAdditionalServiceInformation(
      final List<TspService> tspServices) {
    return tspServices.stream().flatMap(this::extractAdditionalServiceInformation).toList();
  }

  protected String findMatchingTslOcspUrl(
      final List<AdditionalServiceInformationType> asiList, final String aiaOcspUrl) {
    return asiList.stream()
        .filter(asi -> isOcspUrlMatch(asi, aiaOcspUrl))
        .map(this::extractTslOcspUrl)
        .findFirst()
        .orElse(aiaOcspUrl);
  }

  protected boolean isBNetzAVlService(final TspService tspService) {
    return tspService.hasServiceTypeIdentifier(TslConstants.SERVICE_TYPE_IDENTIFIER_BNETZAVL);
  }

  protected java.util.stream.Stream<AdditionalServiceInformationType>
      extractAdditionalServiceInformation(final TspService tspService) {
    return tspService
        .getTspServiceType()
        .getServiceInformation()
        .getServiceInformationExtensions()
        .getExtension()
        .stream()
        .map(ExtensionType::getContent)
        .flatMap(List::stream)
        // some JAXB implementations wrap the AdditionalServiceInformationType in a JAXBElement
        // unwrap such elements before filtering/casting
        .map(
            obj -> {
              if (obj instanceof jakarta.xml.bind.JAXBElement) {
                return ((jakarta.xml.bind.JAXBElement<?>) obj).getValue();
              }
              return obj;
            })
        .filter(AdditionalServiceInformationType.class::isInstance)
        .map(AdditionalServiceInformationType.class::cast);
  }

  protected boolean isOcspUrlMatch(
      final AdditionalServiceInformationType asi, final String aiaOcspUrl) {
    final String infoValue = asi.getInformationValue();
    if (infoValue == null) {
      return false;
    }
    final String[] urls = infoValue.trim().split("\\s+");
    return urls.length >= 2 && urls[0].equals(aiaOcspUrl);
  }

  protected String extractTslOcspUrl(final AdditionalServiceInformationType asi) {
    final String[] urls = asi.getInformationValue().trim().split("\\s+");
    return urls[1];
  }
}
