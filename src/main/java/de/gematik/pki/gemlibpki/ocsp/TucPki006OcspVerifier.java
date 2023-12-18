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

import static de.gematik.pki.gemlibpki.ocsp.OcspConstants.OCSP_TIME_TOLERANCE_MILLISECONDS;
import static de.gematik.pki.gemlibpki.ocsp.OcspResponseGenerator.verifyHashAlgoSupported;
import static de.gematik.pki.gemlibpki.ocsp.OcspUtils.getBasicOcspResp;
import static de.gematik.pki.gemlibpki.ocsp.OcspUtils.getFirstSingleResp;
import static de.gematik.pki.gemlibpki.utils.CertReader.readX509;
import static de.gematik.pki.gemlibpki.utils.GemLibPkiUtils.calculateSha256;
import static org.bouncycastle.internal.asn1.isismtt.ISISMTTObjectIdentifiers.id_isismtt_at_certHash;

import de.gematik.pki.gemlibpki.error.ErrorCode;
import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.tsl.TslConstants;
import de.gematik.pki.gemlibpki.tsl.TspInformationProvider;
import de.gematik.pki.gemlibpki.tsl.TspService;
import de.gematik.pki.gemlibpki.tsl.TspServiceSubset;
import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import eu.europa.esig.trustedlist.jaxb.tsl.DigitalIdentityType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceType;
import java.security.MessageDigest;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.isismtt.ocsp.CertHash;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

/**
 * Entry point to access a verification of ocsp responses regarding standard process called
 * TucPki006. This class works with parameterized variables (defined by builder pattern) and with
 * given variables provided during runtime (method parameters).
 */
@RequiredArgsConstructor(access = AccessLevel.PROTECTED)
@Builder
@Slf4j
public class TucPki006OcspVerifier {

  @NonNull protected final String productType;
  @NonNull protected final List<TspService> tspServiceList;
  @NonNull protected final X509Certificate eeCert;
  @NonNull protected final OCSPResp ocspResponse;
  @Builder.Default protected final boolean enforceCertHashCheck = true;

  /**
   * Performs TUC_PKI_006 checks (OCSP verification) against current date time.
   *
   * @throws GemPkiException thrown in case of failed verification against gemSpec_PKI TUC_PKI_006
   */
  public void performTucPki006Checks() throws GemPkiException {
    performTucPki006Checks(GemLibPkiUtils.now());
  }

  /**
   * Performs TUC_PKI_006 checks (OCSP verification) against given date time as reference date
   *
   * @param referenceDate reference date to check against if the certificate is revoked, as well
   *     thisUpdate, producedAt, nextUpdate
   * @throws GemPkiException thrown in case of failed verification against gemSpec_PKI TUC_PKI_006
   */
  public void performTucPki006Checks(@NonNull final ZonedDateTime referenceDate)
      throws GemPkiException {
    log.info("Performing OCSP checks...");

    verifyOcspResponseSignature();
    verifyStatus(referenceDate);
    verifyCertHash();

    verifyThisUpdate(referenceDate);
    verifyProducedAt(referenceDate);
    verifyNextUpdate(referenceDate);

    verifyOcspResponseCertId();

    log.info("OCSP validation successfully finished.");
  }

  /**
   * Verify th status of the parameterized ocsp response
   *
   * @param referenceDate reference date for the revocation time to check against
   * @throws GemPkiException thrown if response status is not SUCCESSFUL (0)
   */
  protected void verifyStatus(@NonNull final ZonedDateTime referenceDate) throws GemPkiException {
    if (ocspResponse.getStatus() != OCSPResponseStatus.SUCCESSFUL) {
      throw new GemPkiException(productType, ErrorCode.TE_1058_OCSP_STATUS_ERROR);
    }

    final CertificateStatus certificateStatus = getFirstSingleResp(ocspResponse).getCertStatus();

    if (CertificateStatus.GOOD == certificateStatus) {
      return;
    }

    if (certificateStatus instanceof final RevokedStatus revokedStatus) {

      final ZonedDateTime revocationTime =
          ZonedDateTime.ofInstant(revokedStatus.getRevocationTime().toInstant(), ZoneOffset.UTC);

      if (revocationTime.isAfter(referenceDate)) {
        return;
      }

      throw new GemPkiException(productType, ErrorCode.SW_1047_CERT_REVOKED);

    } else {
      // the only remaining case: certificateStatus instanceof UnknownStatus
      throw new GemPkiException(productType, ErrorCode.TW_1044_CERT_UNKNOWN);
    }
  }

  /**
   * Verify th status of the parameterized ocsp response
   *
   * @throws GemPkiException thrown if response status is not SUCCESSFUL (0)
   */
  protected void verifyStatus() throws GemPkiException {
    verifyStatus(GemLibPkiUtils.now());
  }

  /**
   * Verify that thisUpdate of the OCSP response is within its tolerance of {@link
   * OcspConstants#OCSP_TIME_TOLERANCE_MILLISECONDS} in the future. Throws an exception if not.
   *
   * @param referenceDate a reference date to check thisUpdate against
   * @throws GemPkiException thrown if ocsp thisUpdate is in future out of tolerance
   */
  protected void verifyThisUpdate(@NonNull final ZonedDateTime referenceDate)
      throws GemPkiException {
    final SingleResp singleResp = getFirstSingleResp(ocspResponse);

    final Instant thisUpdateInstant = singleResp.getThisUpdate().toInstant();
    final ZonedDateTime thisUpdate = ZonedDateTime.ofInstant(thisUpdateInstant, ZoneOffset.UTC);

    verifyToleranceForFuture(thisUpdate, referenceDate, "thisUpdate");
  }

  /**
   * Verify that thisProducedAt of the OCSP response is within its tolerance of {@link
   * OcspConstants#OCSP_TIME_TOLERANCE_MILLISECONDS} in pas and future. Throws an exception if not.
   *
   * @param referenceDate a reference date to check producedAt against
   * @throws GemPkiException thrown if ocsp producedAt is out of tolerance
   */
  protected void verifyProducedAt(@NonNull final ZonedDateTime referenceDate)
      throws GemPkiException {
    final BasicOCSPResp basicOcspResponse = getBasicOcspResp(ocspResponse);

    final Instant producedAtInstant = basicOcspResponse.getProducedAt().toInstant();
    final ZonedDateTime producedAt = ZonedDateTime.ofInstant(producedAtInstant, ZoneOffset.UTC);

    verifyToleranceForPast(producedAt, referenceDate, "producedAt");
    verifyToleranceForFuture(producedAt, referenceDate, "producedAt");
  }

  /**
   * Verify that nextUpdate of the OCSP response is within its tolerance of {@link
   * OcspConstants#OCSP_TIME_TOLERANCE_MILLISECONDS} in the past. Throws an exception if not. The
   * verification is not performed, if nextUpdate is not available.
   *
   * @param referenceDate a reference date to check nextUpdate against
   * @throws GemPkiException thrown if ocsp nextUpdate is in past out of tolerance
   */
  protected void verifyNextUpdate(@NonNull final ZonedDateTime referenceDate)
      throws GemPkiException {
    final SingleResp singleResp = getFirstSingleResp(ocspResponse);

    if (singleResp.getNextUpdate() == null) {
      log.info("nextUpdate is not set: its verification is not performed");
      return;
    }

    final Instant nextUpdateInstant = singleResp.getNextUpdate().toInstant();
    final ZonedDateTime nextUpdate = ZonedDateTime.ofInstant(nextUpdateInstant, ZoneOffset.UTC);

    verifyToleranceForPast(nextUpdate, referenceDate, "nextUpdate");
  }

  private void verifyToleranceForFuture(
      final ZonedDateTime dateToVerify, final ZonedDateTime referenceDate, final String dateName)
      throws GemPkiException {

    final ZonedDateTime futureTolerance =
        referenceDate.plus(OCSP_TIME_TOLERANCE_MILLISECONDS, ChronoUnit.MILLIS);

    if (dateToVerify.isAfter(futureTolerance)) {

      log.error(
          "The interval for {} of the OCSP response {} is outside of the allowed {} seconds in the"
              + " future {}.",
          dateName,
          dateToVerify,
          TimeUnit.MILLISECONDS.toSeconds(OCSP_TIME_TOLERANCE_MILLISECONDS),
          referenceDate);
      throw new GemPkiException(productType, ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR);
    }
  }

  private void verifyToleranceForPast(
      final ZonedDateTime dateToVerify, final ZonedDateTime referenceDate, final String dateName)
      throws GemPkiException {

    final ZonedDateTime pastTolerance =
        referenceDate.minus(OCSP_TIME_TOLERANCE_MILLISECONDS, ChronoUnit.MILLIS);

    if (dateToVerify.isBefore(pastTolerance)) {
      log.error(
          "The interval for {} of the OCSP response {} is outside of the allowed {} seconds in the"
              + " past {}.",
          dateName,
          dateToVerify,
          TimeUnit.MILLISECONDS.toSeconds(OCSP_TIME_TOLERANCE_MILLISECONDS),
          referenceDate);
      throw new GemPkiException(productType, ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR);
    }
  }

  /**
   * Verifies teh cert hash of the parameterized OCSP Response against the certificate.
   *
   * @throws GemPkiException thrown if the hash is missing or does not match the hash over the
   *     certificate.
   */
  protected void verifyCertHash() throws GemPkiException {
    if (!enforceCertHashCheck) {
      log.info("enforceCertHashCheck=false: verifyCertHash is not performed");
      return;
    }
    try {
      final ASN1Encodable singleOcspRespAsn1 =
          getFirstSingleResp(ocspResponse).getExtension(id_isismtt_at_certHash).getParsedValue();
      final byte[] ocspCertHashBytes =
          CertHash.getInstance(singleOcspRespAsn1).getCertificateHash();
      final byte[] eeCertHashBytes = calculateSha256(GemLibPkiUtils.certToBytes(eeCert));

      if (!MessageDigest.isEqual(ocspCertHashBytes, eeCertHashBytes)) {
        throw new GemPkiException(productType, ErrorCode.SE_1041_CERTHASH_MISMATCH);
      }
    } catch (final NullPointerException e) {
      throw new GemPkiException(productType, ErrorCode.SE_1040_CERTHASH_EXTENSION_MISSING);
    }
  }

  private X509Certificate getFirstCertificate(final TSPServiceType tspServiceType) {
    return readX509(
        tspServiceType
            .getServiceInformation()
            .getServiceDigitalIdentity()
            .getDigitalId()
            .get(0)
            .getX509Certificate());
  }

  private boolean isServiceTypeIdentifierOcsp(final TSPServiceType tspServiceType) {

    final String targetServiceTypeIdentifier =
        tspServiceType.getServiceInformation().getServiceTypeIdentifier();

    return targetServiceTypeIdentifier.equals(TslConstants.STI_OCSP);
  }

  private boolean isSameCertificate(
      final TSPServiceType tspServiceType, final byte[] derX509EeCert) {

    final List<DigitalIdentityType> digitalIdentityTypes =
        tspServiceType.getServiceInformation().getServiceDigitalIdentity().getDigitalId();

    final Optional<DigitalIdentityType> matchedDigitalIdentityType =
        digitalIdentityTypes.stream()
            .filter(
                digitalIdentityType -> {
                  final byte[] derX509EeCert2 =
                      GemLibPkiUtils.calculateSha256(digitalIdentityType.getX509Certificate());
                  return Arrays.equals(derX509EeCert, derX509EeCert2);
                })
            .findAny();

    return matchedDigitalIdentityType.isPresent();
  }

  private X509Certificate getOcspSignerFromTsl(final X509Certificate x509EeCert)
      throws GemPkiException {

    final byte[] derX509EeCert;
    try {
      derX509EeCert = GemLibPkiUtils.calculateSha256(x509EeCert.getEncoded());
    } catch (final CertificateEncodingException e) {
      throw new GemPkiRuntimeException("Fehler beim lesen des OCSP Signers aus der Response.", e);
    }

    final Optional<TspService> matchedTspService =
        tspServiceList.stream()
            .filter(
                tspService ->
                    isServiceTypeIdentifierOcsp(tspService.getTspServiceType())
                        && isSameCertificate(tspService.getTspServiceType(), derX509EeCert))
            .findAny();

    return getFirstCertificate(
        matchedTspService
            .orElseThrow(
                () -> new GemPkiException(productType, ErrorCode.SE_1030_OCSP_CERT_MISSING))
            .getTspServiceType());
  }

  private X509Certificate getSignerFromOcspResponse() {
    final BasicOCSPResp basicOcspResp = getBasicOcspResp(ocspResponse);

    if (basicOcspResp.getCerts().length != 1) {
      throw new GemPkiRuntimeException("Nicht genau 1 Zertifikat in OCSP-Response gefunden.");
    }

    final X509CertificateHolder x509CertificateHolder = basicOcspResp.getCerts()[0];

    try {
      return new JcaX509CertificateConverter().getCertificate(x509CertificateHolder);
    } catch (final CertificateException e) {
      throw new GemPkiRuntimeException(
          "Fehler beim lesen der OCSP Signer Zertifikates aus der OCSP Response.", e);
    }
  }

  /**
   * Verifies the OCSP response signature against the matching certificate found in the TSL.
   *
   * @throws GemPkiException thrown if the signature is not valid, or the certificate cannot be
   *     found in the TSL.
   */
  protected void verifyOcspResponseSignature() throws GemPkiException {
    final X509Certificate ocspSignerInTsl = getOcspSignerFromTsl(getSignerFromOcspResponse());
    final BasicOCSPResp basicOcspResp = getBasicOcspResp(ocspResponse);
    try {
      final ContentVerifierProvider cvp =
          new JcaContentVerifierProviderBuilder()
              .setProvider(BouncyCastleProvider.PROVIDER_NAME)
              .build(ocspSignerInTsl.getPublicKey());
      if (!basicOcspResp.isSignatureValid(cvp)) {
        throw new GemPkiException(productType, ErrorCode.SE_1031_OCSP_SIGNATURE_ERROR);
      }
    } catch (final OCSPException | OperatorCreationException e) {
      throw new GemPkiRuntimeException(
          "Interner Fehler beim verifizieren der Ocsp Response Signatur.", e);
    }
  }

  /**
   * Verifies the OCSP cert id of the parameterized OCSP response against the cert id of the
   * corresponding parameterized OCSP request.
   *
   * @throws GemPkiException thrown if the cert ids does not match.
   */
  protected void verifyOcspResponseCertId() throws GemPkiException {

    final SingleResp singleResp = getFirstSingleResp(ocspResponse);
    final CertificateID respCertId = singleResp.getCertID();

    final AlgorithmIdentifier algorithmIdentifier = respCertId.toASN1Primitive().getHashAlgorithm();

    final TspServiceSubset tspServiceSubset =
        new TspInformationProvider(tspServiceList, productType).getIssuerTspServiceSubset(eeCert);

    final CertificateID computedCertId =
        OcspRequestGenerator.createCertificateId(
            eeCert.getSerialNumber(), tspServiceSubset.getX509IssuerCert(), algorithmIdentifier);

    try {
      verifyHashAlgoSupported(algorithmIdentifier.getAlgorithm());
    } catch (final GemPkiRuntimeException e) {
      throw new GemPkiException(productType, ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR);
    }

    if (!respCertId.equals(computedCertId)) {
      throw new GemPkiException(productType, ErrorCode.TE_1029_OCSP_CHECK_REVOCATION_ERROR);
    }
  }
}
