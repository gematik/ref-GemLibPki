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

package de.gematik.pki.gemlibpki.tsl;

import static de.gematik.pki.gemlibpki.ocsp.OcspConstants.OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_FUTURE_MILLISECONDS;
import static de.gematik.pki.gemlibpki.ocsp.OcspConstants.OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_PAST_MILLISECONDS;
import static de.gematik.pki.gemlibpki.utils.ResourceReader.getUrlFromResources;
import static javax.xml.XMLConstants.W3C_XML_SCHEMA_NS_URI;

import de.gematik.pki.gemlibpki.certificate.CertificateProfile;
import de.gematik.pki.gemlibpki.certificate.TucPki018Verifier;
import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.ocsp.OcspConstants;
import de.gematik.pki.gemlibpki.ocsp.OcspRespCache;
import de.gematik.pki.gemlibpki.utils.CertReader;
import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.gemlibpki.validators.ValidityValidator;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceType;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Optional;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.transform.dom.DOMSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

/**
 * Entry point to access a verification of TSLs regarding standard process called TucPki001. This
 * class works with parameterized variables (defined by builder pattern) and with given variables
 * provided by runtime (method parameters).
 *
 * <p>Member "currentTrustedServices" holds the services of the current trust store (the established
 * trust space from former successful tsl parsings)
 */
@Slf4j
@RequiredArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class TucPki001Verifier {

  @NonNull protected final String productType;

  @NonNull protected final List<TspService> currentTrustedServices;

  @NonNull protected final String currentTslId;

  @NonNull protected final BigInteger currentTslSeqNr;

  protected final byte @NonNull [] tslToCheck;
  @Builder.Default protected final boolean withOcspCheck = true;
  protected final OcspRespCache ocspRespCache;

  @Builder.Default
  protected final int ocspTimeoutSeconds = OcspConstants.DEFAULT_OCSP_TIMEOUT_SECONDS;

  @Builder.Default
  private final int ocspTimeToleranceProducedAtFutureMilliseconds =
      OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_FUTURE_MILLISECONDS;

  @Builder.Default
  private final int ocspTimeToleranceProducedAtPastMilliseconds =
      OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_PAST_MILLISECONDS;

  @Builder.Default protected final boolean tolerateOcspFailure = false;

  @Builder.Default private ValidityValidator validityValidator = null;

  /**
   * Performs TSL validity verification: This method is implemented static, as it ist not part of
   * the checks of TucPki001. The product has to call the method separately to decide if the current
   * tsl can be used for checks according to the TUC
   *
   * @throws GemPkiException thrown when TSL is not valid in time anymore
   */
  public static void verifyTslValidity(
      final ZonedDateTime referenceDate,
      final int tslGracePeriod,
      final TrustStatusListType tsl,
      final String productType)
      throws GemPkiException {

    final XMLGregorianCalendar xmlNextUpdate =
        tsl.getSchemeInformation().getNextUpdate().getDateTime();

    final ZonedDateTime nextUpdate =
        ZonedDateTime.ofInstant(xmlNextUpdate.toGregorianCalendar().toInstant(), ZoneOffset.UTC);

    final ZonedDateTime tslValidityThreshold = referenceDate.minusDays(tslGracePeriod);

    if (nextUpdate.isAfter(referenceDate)) {
      return;
    }

    if (nextUpdate.isAfter(tslValidityThreshold)) {
      log.warn(ErrorCode.SW_1008_VALIDITY_WARNING_1.getErrorMessage(productType));
      return;
    }

    throw new GemPkiException(productType, ErrorCode.SW_1009_VALIDITY_WARNING_2);
  }

  /**
   * Performs TUC_PKI_001 checks (TSL verification)
   *
   * @return {@link TrustAnchorUpdate} instance
   * @throws GemPkiException thrown when TSL is not conform to gemSpec_PKI
   */
  public Optional<TrustAnchorUpdate> performTucPki001Checks() throws GemPkiException {
    log.debug("TUC_PKI_001 Checks...");

    // check for well-formed xml
    validateWellFormedXml();

    // TUC_PKI_020 „XML-Dokument validieren“
    validateAgainstXsdSchemas();

    final X509Certificate tslSigner = getTslSignerCertificate();

    // TUC_PKI_011 „Prüfung des TSL-Signer-Zertifikates“
    final TucPki018Verifier certVerifier =
        TucPki018Verifier.builder()
            .productType(productType)
            .ocspRespCache(ocspRespCache)
            .tspServiceList(currentTrustedServices)
            .certificateProfiles(List.of(CertificateProfile.CERT_PROFILE_C_TSL_SIG))
            .withOcspCheck(withOcspCheck)
            .ocspTimeToleranceProducedAtFutureMilliseconds(
                ocspTimeToleranceProducedAtFutureMilliseconds)
            .ocspTimeToleranceProducedAtPastMilliseconds(
                ocspTimeToleranceProducedAtPastMilliseconds)
            .ocspTimeoutSeconds(ocspTimeoutSeconds)
            .tolerateOcspFailure(tolerateOcspFailure)
            .build();
    certVerifier.performTucPki018Checks(tslSigner);

    // TUC_PKI_012 XML-Signatur-Prüfung
    checkTslSignature(tslSigner);

    // TUC_PKI_019 steps 5 and 6
    checkTslIdAndTslSeqNr();

    // Step 5 - TUC_PKI_013 Import TI-Vertrauensanker aus TSL
    return getVerifiedAnnouncedTrustAnchorUpdate();
  }

  protected void validateWellFormedXml() throws GemPkiException {
    try {
      TslConverter.bytesToDoc(tslToCheck);
    } catch (final GemPkiRuntimeException e) {
      if (e.getCause() instanceof SAXException) {
        throw new GemPkiException(productType, ErrorCode.TE_1011_TSL_NOT_WELLFORMED);
      }
      throw e;
    }
  }

  protected void validateAgainstXsdSchemas() throws GemPkiException {
    validateXsd();
    validateAdditionalTypes();
    validateSie();
    log.info("Schema validation successful!");
  }

  Validator getValidator(final String scheme) {
    final SchemaFactory sf = SchemaFactory.newInstance(W3C_XML_SCHEMA_NS_URI); // NOSONAR
    final URL schemaUrl = getUrlFromResources(scheme, TucPki001Verifier.class);
    final Schema compiledSchema;
    try {
      compiledSchema = sf.newSchema(schemaUrl);
    } catch (final SAXException e) {
      throw new GemPkiRuntimeException("Error during parsing of schema file.", e);
    }

    return compiledSchema.newValidator();
  }

  void validateAgainstXsd(final String scheme) throws GemPkiException {

    final Validator validator = getValidator(scheme);
    final Document tslToCheckDoc = TslConverter.bytesToDoc(tslToCheck);
    try {
      validator.validate(new DOMSource(tslToCheckDoc));
    } catch (final SAXException e) {
      throw new GemPkiException(productType, ErrorCode.TE_1012_TSL_SCHEMA_NOT_VALID, e);
    } catch (final IOException e) {
      throw new GemPkiRuntimeException("Error reading schema file.", e);
    }
  }

  private void validateAdditionalTypes() throws GemPkiException {
    validateAgainstXsd("schemas/ts_102231v030102_additionaltypes_xsd.xsd");
  }

  private void validateXsd() throws GemPkiException {
    validateAgainstXsd("schemas/ts_102231v030102_xsd.xsd");
  }

  private void validateSie() throws GemPkiException {
    validateAgainstXsd("schemas/ts_102231v030102_sie_xsd.xsd");
  }

  /** Class to keep information about announced trust anchor. */
  @Getter
  @AllArgsConstructor
  public static class TrustAnchorUpdate {

    private X509Certificate futureTrustAnchor;
    private ZonedDateTime statusStartingTime;

    /**
     * Returns true is the announced trust anchor is to activate comparing to the current timestamp.
     *
     * @return boolean if the new trust anchor is active (status starting time is reached)
     */
    public boolean isToActivateNow() {
      return isToActivate(GemLibPkiUtils.now());
    }

    /**
     * Returns true is the announced trust anchor is to activate comparing to the reference date.
     *
     * @param referenceDate date to check against time from
     * @return boolean if the new trust anchor is active (status starting time is reached according
     *     to reference date)
     */
    public boolean isToActivate(final ZonedDateTime referenceDate) {
      return statusStartingTime.isBefore(referenceDate);
    }
  }

  private static List<TSPServiceType> getTrustAnchorTspServices(final byte[] tsl) {
    return new TslInformationProvider(TslConverter.bytesToTslUnsigned(tsl))
        .getFilteredTspServices(List.of(TslConstants.STI_SRV_CERT_CHANGE)).stream()
            .map(TspService::getTspServiceType)
            .toList();
  }

  protected Optional<TrustAnchorUpdate> getVerifiedAnnouncedTrustAnchorUpdate() {
    return getVerifiedAnnouncedTrustAnchorUpdate(GemLibPkiUtils.now());
  }

  private void initializeValidator() {
    if (validityValidator != null) {
      return;
    }

    validityValidator = new ValidityValidator(productType);
  }

  private Optional<TrustAnchorUpdate> getVerifiedAnnouncedTrustAnchorUpdate(
      final ZonedDateTime referenceDate) {

    log.debug("check for a trust anchor for update");
    try {
      final List<TSPServiceType> certChangeTspServiceTypeList =
          getTrustAnchorTspServices(tslToCheck);

      if (certChangeTspServiceTypeList.isEmpty()) {
        log.debug("no trust anchors for update found");
        return Optional.empty();
      }

      if (certChangeTspServiceTypeList.size() > 1) {
        log.debug("multiple trust anchors for update found -> ignoring trust anchor update");
        log.warn(ErrorCode.SE_1003_MULTIPLE_TRUST_ANCHOR.getErrorMessage(productType));
        return Optional.empty();
      }

      log.debug("one trust anchor for update found: starting its verification");

      final TSPServiceType certChangeTspServiceType = certChangeTspServiceTypeList.get(0);

      final ZonedDateTime statusStartingTime =
          certChangeTspServiceType
              .getServiceInformation()
              .getStatusStartingTime()
              .toGregorianCalendar()
              .toZonedDateTime();

      final byte[] futureTrustAnchorBytes =
          certChangeTspServiceType
              .getServiceInformation()
              .getServiceDigitalIdentity()
              .getDigitalId()
              .get(0)
              .getX509Certificate();

      final X509Certificate futureTrustAnchor =
          CertReader.readX509(productType, futureTrustAnchorBytes);

      initializeValidator();

      validityValidator.validateCertificate(futureTrustAnchor, referenceDate);

      log.debug(
          "verification of the trust anchor successful: certSerialNr {}, statusStartingTime {}",
          futureTrustAnchor.getSerialNumber(),
          statusStartingTime);

      return Optional.of(new TrustAnchorUpdate(futureTrustAnchor, statusStartingTime));

    } catch (final GemPkiException e) {
      log.info(e.getError().getErrorMessage(productType));
      log.info("Verification of the trust anchor for update anchor failed.", e);
    } catch (final RuntimeException e) {
      log.info("Extraction and processing of the trust anchor for update failed.", e);
    }

    return Optional.empty();
  }

  protected X509Certificate getTslSignerCertificate() throws GemPkiException {
    try {
      return TslUtils.getFirstTslSignerCertificate(TslConverter.bytesToTslUnsigned(tslToCheck));
    } catch (final RuntimeException e) {
      throw new GemPkiException(productType, ErrorCode.TE_1002_TSL_CERT_EXTRACTION_ERROR);
    }
  }

  // checks Tsl signature according to TUC_PKI_012
  private void checkTslSignature(final X509Certificate tslSigner) throws GemPkiException {

    final Document tslToCheckDoc = TslConverter.bytesToDoc(tslToCheck);

    final X509Certificate trustAnchor =
        new TspInformationProvider(currentTrustedServices, productType)
            .getIssuerTspServiceSubset(tslSigner)
            .getX509IssuerCert();

    if (!TslValidator.checkSignature(tslToCheckDoc, trustAnchor)) {
      throw new GemPkiException(productType, ErrorCode.SE_1013_XML_SIGNATURE_ERROR);
    }
  }

  // TUC_PKI_019 steps 5 and 6
  private void checkTslIdAndTslSeqNr() throws GemPkiException {
    final TrustStatusListType tslUnsigned = TslConverter.bytesToTslUnsigned(tslToCheck);
    final String newTslId = tslUnsigned.getId();
    final BigInteger newTslSeqNr = TslReader.getTslSeqNr(tslUnsigned);

    if ((newTslSeqNr.compareTo(currentTslSeqNr) > 0) && !currentTslId.equals(newTslId)) {
      return;
    }

    final String errorMessage = getErrorMessage(newTslSeqNr, newTslId);

    log.debug("irregular differences between new and current TSLs were detected");
    log.debug("  currentTsl: tslSeqNr {}, id {}", currentTslSeqNr, currentTslId);
    log.debug("  newTsl:     tslSeqNr {}, id {}", newTslSeqNr, newTslId);
    log.debug("  --> {}", errorMessage);

    throw new GemPkiException(productType, ErrorCode.SE_1007_TSL_ID_INCORRECT);
  }

  private String getErrorMessage(final BigInteger newTslSeqNr, final String newTslId) {

    if ((newTslSeqNr.compareTo(currentTslSeqNr) == 0) && currentTslId.equals(newTslId)) {
      return "check0: no changes in new tslSeqNr and tslId";
    }

    if ((newTslSeqNr.compareTo(currentTslSeqNr) == 0) && !currentTslId.equals(newTslId)) {
      return "check2: new tslSeqNr and current tslSeqNr are equal, but ids differ";
    }

    if ((newTslSeqNr.compareTo(currentTslSeqNr) > 0) && currentTslId.equals(newTslId)) {
      return "check3: new tslSeqNr greater than current tslSeqNr, but ids are equal";
    }

    // case  if newTslSeqNr.compareTo(currentTslSeqNr) < 0
    return "check1: new tslSeqNr is smaller than current tslSeqNr";
  }
}
