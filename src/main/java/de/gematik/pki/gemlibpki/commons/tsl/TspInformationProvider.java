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

import de.gematik.pki.gemlibpki.commons.error.ErrorCode;
import de.gematik.pki.gemlibpki.commons.exception.GemPkiException;
import de.gematik.pki.gemlibpki.commons.utils.CertReader;
import eu.europa.esig.trustedlist.jaxb.tsl.AttributedNonEmptyURIType;
import eu.europa.esig.trustedlist.jaxb.tsl.DigitalIdentityListType;
import eu.europa.esig.trustedlist.jaxb.tsl.DigitalIdentityType;
import eu.europa.esig.trustedlist.jaxb.tsl.InternationalNamesType;
import eu.europa.esig.trustedlist.jaxb.tsl.ServiceHistoryInstanceType;
import eu.europa.esig.trustedlist.jaxb.tsl.ServiceHistoryType;
import eu.europa.esig.trustedlist.jaxb.tsl.ServiceSupplyPointsType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceInformationType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceType;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.BiFunction;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;

/** Class to extract and compose information about a {@link TspService}. */
@RequiredArgsConstructor
@Slf4j
public class TspInformationProvider {

  private final List<TspService> tspServices;
  private final String productType;

  /**
   * Verify AKI (authority key identifier - an X.509 v3 certificate extension - derived from the
   * public key of the given issuer certificate) must match with SKI (subject key identifier - an
   * X.509 v3 certificate extension - derived from the public key of the given end-entity
   * certificate).
   *
   * @param x509EeCert end-entity certificate
   * @param x509IssuerCert issuer certificate determined from TSL file
   * @return true when aki matches ski otherwise false
   */
  private static boolean verifyAkiMatchesSki(
      final X509Certificate x509EeCert, final X509Certificate x509IssuerCert) {

    final BiFunction<X509Certificate, ASN1ObjectIdentifier, Optional<ASN1OctetString>> getAsOctet =
        (cert, identifier) -> {
          final byte[] keyIdentifier = cert.getExtensionValue(identifier.getId());
          return Optional.ofNullable(ASN1OctetString.getInstance(keyIdentifier));
        };

    final Optional<ASN1OctetString> skiAsOctet =
        getAsOctet.apply(x509IssuerCert, Extension.subjectKeyIdentifier);

    if (skiAsOctet.isEmpty()) {
      log.debug(
          "Extension SUBJECT_KEY_IDENTIFIER_OID: {} konnte in {} nicht gefunden werden.",
          Extension.subjectKeyIdentifier.getId(),
          x509IssuerCert.getSubjectX500Principal());
      return false;
    }
    final SubjectKeyIdentifier subKeyIdentifier =
        SubjectKeyIdentifier.getInstance(skiAsOctet.get().getOctets());

    final Optional<ASN1OctetString> akiAsOctet =
        getAsOctet.apply(x509EeCert, Extension.authorityKeyIdentifier);

    if (akiAsOctet.isEmpty()) {
      log.debug(
          "Extension AUTHORITY_KEY_IDENTIFIER_OID: {} konnte in {} nicht gefunden werden.",
          Extension.authorityKeyIdentifier.getId(),
          x509EeCert.getSubjectX500Principal());
      return false;
    }

    final ASN1Primitive akiSequenceAsOctet;
    try {
      akiSequenceAsOctet = ASN1Primitive.fromByteArray(akiAsOctet.get().getOctets());
    } catch (final IOException e) {
      log.debug(
          "Octets des AUTHORITY_KEY_IDENTIFIER konnten in {} nicht gefunden werden.",
          x509EeCert.getSubjectX500Principal());
      log.trace("{}", e.toString());
      return false;
    }
    final AuthorityKeyIdentifier authKeyIdentifier =
        AuthorityKeyIdentifier.getInstance(akiSequenceAsOctet);
    return Arrays.equals(
        subKeyIdentifier.getKeyIdentifier(), authKeyIdentifier.getKeyIdentifierOctets());
  }

  /**
   * Get timestamp of status change of given TspService from TSL file.
   *
   * @param issuerTspService TspService from TSL file
   * @return ZonedDateTime timestamp of status change
   */
  private static ZonedDateTime getCertificateAuthorityStatusStartingTime(
      final TspService issuerTspService) {
    return issuerTspService
        .getTspServiceType()
        .getServiceInformation()
        .getStatusStartingTime()
        .toGregorianCalendar()
        .toZonedDateTime();
  }

  private static Optional<ZonedDateTime> getStatusStartingTime(
      final ServiceHistoryInstanceType serviceHistoryInstance) {
    return Optional.ofNullable(serviceHistoryInstance)
        .map(ServiceHistoryInstanceType::getStatusStartingTime)
        .map(statusStartingTime -> statusStartingTime.toGregorianCalendar().toZonedDateTime());
  }

  private static List<TspServiceStatusHistoryEntry> getServiceStatusHistory(
      final TspService tspService) {
    return Optional.ofNullable(tspService)
        .map(TspService::getTspServiceType)
        .map(TSPServiceType::getServiceHistory)
        .map(ServiceHistoryType::getServiceHistoryInstance)
        .stream()
        .flatMap(List::stream)
        .filter(Objects::nonNull)
        .map(
            serviceHistoryInstance ->
                new TspServiceStatusHistoryEntry(
                    serviceHistoryInstance.getServiceStatus(),
                    getStatusStartingTime(serviceHistoryInstance).orElse(null)))
        .toList();
  }

  /**
   * Compose an information subset of a TspService if one of its issuers signed the given end-entity
   * certificate.
   *
   * @param x509EeCert The end-entity certificate
   * @return information subset of a TspService {@link TspServiceSubset}
   * @throws GemPkiException exception thrown if certificate cannot be found
   */
  public TspServiceSubset getIssuerTspServiceSubset(@NonNull final X509Certificate x509EeCert)
      throws GemPkiException {
    final Pair<TspService, X509Certificate> pair = getIssuerTspServiceAndIssuerCert(x509EeCert);

    final TspService tspService = pair.getLeft();
    final X509Certificate x509IssuerCert = pair.getRight();

    return TspServiceSubset.builder()
        .x509IssuerCert(x509IssuerCert)
        .serviceStatus(tspService.getTspServiceType().getServiceInformation().getServiceStatus())
        .statusStartingTime(getCertificateAuthorityStatusStartingTime(tspService))
        .serviceSupplyPoint(getFirstServiceSupplyPointFromTspService(tspService))
        .serviceStatusHistory(getServiceStatusHistory(tspService))
        .extensions(
            tspService
                .getTspServiceType()
                .getServiceInformation()
                .getServiceInformationExtensions()
                .getExtension())
        .build();
  }

  /**
   * Compose an information subset of a QES-CA TspService if one of its issuers signed the given
   * end-entity certificate.
   *
   * @param x509EeCert The end-entity certificate
   * @return information subset of a QES-CA TspService {@link TspServiceSubset}
   * @throws GemPkiException exception thrown if certificate cannot be found or is not QES-qualified
   */
  public TspServiceSubset getIssuerQesCaTspServiceSubset(@NonNull final X509Certificate x509EeCert)
      throws GemPkiException {
    try {
      final TspServiceSubset qesCaTspServiceSubset = getIssuerTspServiceSubset(x509EeCert);
      log.debug(
          "QES-CA certificate found in BNetzA-VL: {}",
          qesCaTspServiceSubset.getX509IssuerCert().getSubjectX500Principal());
      return qesCaTspServiceSubset;
    } catch (final GemPkiException e) {
      if (ErrorCode.TE_1027_CA_CERT_MISSING.equals(e.getError())
          || ErrorCode.SE_1023_AUTHORITYKEYID_DIFFERENT.equals(e.getError())) {
        throw new GemPkiException(
            productType, ErrorCode.SE_1059_CA_CERTIFICATE_NOT_QES_QUALIFIED, e);
      }

      throw e;
    }
  }

  private Pair<TspService, X509Certificate> getIssuerTspServiceAndIssuerCert(
      @NonNull final X509Certificate x509EeCert) throws GemPkiException {
    Optional<X509Certificate> foundX509IssuerCert = Optional.empty();
    log.info(
        "Looking for issuer {} in trust store.", x509EeCert.getIssuerX500Principal().getName());
    for (final TspService tspService : tspServices) {
      final Optional<List<DigitalIdentityType>> digitalIds = getProcessableDigitalIds(tspService);
      if (digitalIds.isEmpty()) {
        log.debug("skipped {} due to missing tsp information", getDisplayName(tspService));
        continue;
      }

      for (final DigitalIdentityType dit : digitalIds.get()) {
        final X509Certificate x509IssuerCert =
            CertReader.readX509(productType, dit.getX509Certificate());

        if (x509EeCert.getIssuerX500Principal().equals(x509IssuerCert.getSubjectX500Principal())) {

          if (verifyAkiMatchesSki(x509EeCert, x509IssuerCert)) {
            return Pair.of(tspService, x509IssuerCert);
          }
          foundX509IssuerCert = Optional.of(x509IssuerCert);
        }
      }
    }

    if (foundX509IssuerCert.isEmpty()) {
      throw new GemPkiException(productType, ErrorCode.TE_1027_CA_CERT_MISSING);
    } else {
      throw new GemPkiException(productType, ErrorCode.SE_1023_AUTHORITYKEYID_DIFFERENT);
    }
  }

  /**
   * Returns a TspService if one of its issuers signed the given end-entity certificate.
   *
   * @param x509EeCert The end-entity certificate
   * @return tspService
   * @throws GemPkiException exception thrown if certificate cannot be found
   */
  public TspService getIssuerTspService(@NonNull final X509Certificate x509EeCert)
      throws GemPkiException {
    return getIssuerTspServiceAndIssuerCert(x509EeCert).getLeft();
  }

  /**
   * Get OCSP responder URL from given TspService.
   *
   * @param tspService the given TspService
   * @return ServiceSupplyPoint as string (URL)
   */
  private String getFirstServiceSupplyPointFromTspService(final TspService tspService) {

    final Optional<ServiceSupplyPointsType> serviceSupplyPointsType =
        Optional.ofNullable(
            tspService.getTspServiceType().getServiceInformation().getServiceSupplyPoints());

    if (serviceSupplyPointsType.isEmpty()) {
      return StringUtils.EMPTY;
    }

    final List<AttributedNonEmptyURIType> sspList =
        serviceSupplyPointsType.get().getServiceSupplyPoint();

    if (sspList.isEmpty()) {
      return StringUtils.EMPTY;
    }

    final String firstServiceSupplyPoint = sspList.getFirst().getValue();

    if (firstServiceSupplyPoint.isBlank()) {
      return StringUtils.EMPTY;
    }

    log.debug("First ServiceSupplyPoint was identified: {}", firstServiceSupplyPoint);
    return firstServiceSupplyPoint;
  }

  private Optional<List<DigitalIdentityType>> getProcessableDigitalIds(
      final TspService tspService) {
    return Optional.ofNullable(tspService)
        .map(TspService::getTspServiceType)
        .map(TSPServiceType::getServiceInformation)
        .map(TSPServiceInformationType::getServiceDigitalIdentity)
        .map(DigitalIdentityListType::getDigitalId)
        .map(
            digitalIds ->
                digitalIds.stream()
                    .filter(Objects::nonNull)
                    .filter(TspInformationProvider::containsX509Certificate)
                    .toList())
        .filter(digitalIds -> !digitalIds.isEmpty());
  }

  private static boolean containsX509Certificate(final DigitalIdentityType digitalIdentityType) {
    return digitalIdentityType != null && digitalIdentityType.getX509Certificate() != null;
  }

  private String getDisplayName(final TspService tspService) {
    return Optional.ofNullable(tspService)
        .map(TspService::getTspServiceType)
        .map(TSPServiceType::getServiceInformation)
        .map(TSPServiceInformationType::getServiceName)
        .map(InternationalNamesType::getName)
        .filter(serviceNames -> !serviceNames.isEmpty())
        .map(serviceNames -> serviceNames.getFirst().getValue())
        .filter(StringUtils::isNotBlank)
        .orElse("<unknown tsp service>");
  }
}
