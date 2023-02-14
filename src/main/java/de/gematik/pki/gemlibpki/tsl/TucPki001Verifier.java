/*
 * Copyright (c) 2023 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.pki.gemlibpki.tsl;

import de.gematik.pki.gemlibpki.certificate.CertificateCommonVerification;
import de.gematik.pki.gemlibpki.certificate.CertificateProfile;
import de.gematik.pki.gemlibpki.certificate.TucPki018Verifier;
import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.ocsp.OcspConstants;
import de.gematik.pki.gemlibpki.ocsp.OcspRespCache;
import de.gematik.pki.gemlibpki.utils.CertReader;
import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceType;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Optional;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.w3c.dom.Document;

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
@Builder
public class TucPki001Verifier {

  @NonNull protected final String productType;

  @NonNull protected final List<TspService> currentTrustedServices;

  @NonNull protected final String currentTslId;

  @NonNull protected final BigInteger currentSeqNr;

  protected final byte @NonNull [] tslToCheck;
  @Builder.Default protected final boolean withOcspCheck = true;
  protected final OcspRespCache ocspRespCache;

  @Builder.Default
  protected final int ocspTimeoutSeconds = OcspConstants.DEFAULT_OCSP_TIMEOUT_SECONDS;

  @Builder.Default protected final boolean tolerateOcspFailure = false;

  /**
   * Performs TUC_PKI_001 checks (TSL verification)
   *
   * @return {@link TrustAnchorUpdate} instance
   * @throws GemPkiException thrown when TSL is not conform to gemSpec_PKI
   */
  public Optional<TrustAnchorUpdate> performTucPki001Checks() throws GemPkiException {
    log.debug("TUC_PKI_001 Checks...");

    final X509Certificate tslSigner = getTslSignerCertificate();

    // TUC_PKI_020 „XML-Dokument validieren“

    // TUC_PKI_011 „Prüfung des TSL-Signer-Zertifikates“
    final TucPki018Verifier certVerifier =
        TucPki018Verifier.builder()
            .productType(productType)
            .ocspRespCache(ocspRespCache)
            .tspServiceList(currentTrustedServices)
            .certificateProfiles(List.of(CertificateProfile.CERT_PROFILE_C_TSL_SIG))
            .withOcspCheck(withOcspCheck)
            .ocspTimeoutSeconds(ocspTimeoutSeconds)
            .tolerateOcspFailure(tolerateOcspFailure)
            .build();
    certVerifier.performTucPki18Checks(tslSigner);

    // TUC_PKI_012 XML-Signatur-Prüfung
    checkTslSignature(tslSigner);

    // TUC_PKI_019 steps 5 and 6
    checkTslIdAndSeqNr();

    // Step 5 - TUC_PKI_013 Import TI-Vertrauensanker aus TSL
    return getVerifiedAnnouncedTrustAnchorUpdate();
  }

  @Getter
  @AllArgsConstructor
  public static class TrustAnchorUpdate {

    private X509Certificate futureTrustAnchor;
    private ZonedDateTime statusStartingTime;

    public boolean isToActivateNow() {
      return isToActivate(GemLibPkiUtils.now());
    }

    public boolean isToActivate(final ZonedDateTime referenceDate) {
      return statusStartingTime.isBefore(referenceDate);
    }
  }

  private static List<TSPServiceType> getTrustAnchorTspServices(final byte[] tsl) {
    return new TslInformationProvider(TslConverter.bytesToTsl(tsl))
        .getFilteredTspServices(List.of(TslConstants.STI_SRV_CERT_CHANGE)).stream()
            .map(TspService::getTspServiceType)
            .toList();
  }

  protected Optional<TrustAnchorUpdate> getVerifiedAnnouncedTrustAnchorUpdate() {
    return getVerifiedAnnouncedTrustAnchorUpdate(GemLibPkiUtils.now());
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

      log.debug("one trust anchor for update found: start its verification");

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

      final TspServiceSubset tspServiceTrustAnchorSubset =
          TspServiceSubset.builder().x509IssuerCert(futureTrustAnchor).build();

      CertificateCommonVerification.builder()
          .productType(productType)
          .x509EeCert(futureTrustAnchor)
          .tspServiceSubset(tspServiceTrustAnchorSubset)
          .build()
          .verifyValidity(referenceDate);

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

      final X509Certificate cert =
          TslUtils.getFirstTslSignerCertificate(TslConverter.bytesToTsl(tslToCheck));

      if (cert == null) {
        throw new GemPkiException(productType, ErrorCode.TE_1002_TSL_CERT_EXTRACTION_ERROR);
      }

      return cert;

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
  private void checkTslIdAndSeqNr() throws GemPkiException {
    final TrustStatusListType tsl = TslConverter.bytesToTsl(tslToCheck);
    final String newTslId = tsl.getId();
    final BigInteger newSeqNr = TslReader.getSequenceNumber(tsl);

    if ((newSeqNr.compareTo(currentSeqNr) > 0) && !currentTslId.equals(newTslId)) {
      return;
    }

    String errorMessage = null;

    if ((newSeqNr.compareTo(currentSeqNr) == 0) && currentTslId.equals(newTslId)) {
      errorMessage = "check0: no changes in new seqNr and tslId";
    }

    if (newSeqNr.compareTo(currentSeqNr) < 0) {
      errorMessage = "check1: new seqNr is smaller than current seqNr";
    }

    if ((newSeqNr.compareTo(currentSeqNr) > 0) && currentTslId.equals(newTslId)) {
      errorMessage = "check3: new seqNr greater than current seqNr, but ids are equal";
    }

    if ((newSeqNr.compareTo(currentSeqNr) == 0) && !currentTslId.equals(newTslId)) {
      errorMessage = "check2: new seqNr and current seqNr are equal, but ids differ";
    }

    log.debug("irregular differences between new and current TSLs were detected");
    log.debug("  currentTsl: seqNr {}, id {}", currentSeqNr, currentTslId);
    log.debug("  newTsl:     seqNr {}, id {}", newSeqNr, newTslId);
    log.debug("  --> {}", errorMessage);

    throw new GemPkiException(productType, ErrorCode.SE_1007_TSL_ID_INCORRECT);
  }
}
