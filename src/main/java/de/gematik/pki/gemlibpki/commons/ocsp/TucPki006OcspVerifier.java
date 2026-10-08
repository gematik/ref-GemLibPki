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

package de.gematik.pki.gemlibpki.commons.ocsp;

import static de.gematik.pki.gemlibpki.commons.ocsp.OcspConstants.OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_FUTURE_MILLISECONDS;
import static de.gematik.pki.gemlibpki.commons.ocsp.OcspConstants.OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_PAST_MILLISECONDS;
import static de.gematik.pki.gemlibpki.commons.ocsp.OcspUtils.getBasicOcspResp;
import static de.gematik.pki.gemlibpki.commons.ocsp.OcspUtils.getFirstSingleResp;
import static de.gematik.pki.gemlibpki.commons.utils.GemLibPkiUtils.calculateSha256;
import static org.bouncycastle.internal.asn1.isismtt.ISISMTTObjectIdentifiers.id_isismtt_at_certHash;

import de.gematik.pki.gemlibpki.commons.error.ErrorCode;
import de.gematik.pki.gemlibpki.commons.exception.GemPkiException;
import de.gematik.pki.gemlibpki.commons.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.commons.tsl.TspInformationProvider;
import de.gematik.pki.gemlibpki.commons.tsl.TspService;
import de.gematik.pki.gemlibpki.commons.tsl.TspServiceSubset;
import de.gematik.pki.gemlibpki.commons.utils.GemLibPkiUtils;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.List;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.isismtt.ocsp.CertHash;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

/**
 * Entry point to access verification of ocsp responses regarding a standard process called
 * TucPki006. This class works with parameterized variables (defined by builder pattern) and with
 * given variables provided during runtime (method parameters).
 */
@AllArgsConstructor(access = AccessLevel.PROTECTED)
@Builder
@Slf4j
public class TucPki006OcspVerifier {

  @NonNull protected final String productType;
  @NonNull protected final List<TspService> tspServiceList;
  @NonNull protected final X509Certificate eeCert;
  @NonNull protected final OCSPResp ocspResponse;

  @Builder.Default protected final boolean enforceCertHashCheck = true;

  @Builder.Default
  private int ocspTimeToleranceProducedAtPastMilliseconds =
      OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_PAST_MILLISECONDS;

  @Builder.Default
  private int ocspTimeToleranceProducedAtFutureMilliseconds =
      OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_FUTURE_MILLISECONDS;

  /**
   * Performs TUC_PKI_006 checks (OCSP verification) against the current date time.
   *
   * @throws GemPkiException thrown in case of failed verification against gemSpec_PKI TUC_PKI_006
   */
  public void performTucPki006Checks() throws GemPkiException {
    performTucPki006Checks(GemLibPkiUtils.now());
  }

  /**
   * Performs TUC_PKI_006 checks (OCSP verification) against the given date time as reference date
   *
   * @param referenceDate reference date to check against if the certificate is revoked, as well
   *     thisUpdate, producedAt, nextUpdate
   * @throws GemPkiException thrown in case of failed verification against gemSpec_PKI TUC_PKI_006
   */
  public void performTucPki006Checks(@NonNull final ZonedDateTime referenceDate)
      throws GemPkiException {
    log.info("Performing OCSP checks...");

    verifyOcspResponseSignature();
    verifyOcspResponseChecks(referenceDate);
    log.info("OCSP validation (TUC-PKI-006) successfully finished.");
  }

  public void performChecksForProvidedOcspResponse(@NonNull final ZonedDateTime referenceDate)
      throws GemPkiException {
    log.info("Performing OCSP checks for provided response...");

    verifyOcspResponseSignature();
    verifyCertHash();
    verifyProvidedOcspResponseBasics(referenceDate);

    log.info("OCSP validation for provided response successfully finished.");
  }

  /**
   * Verifies the cert hash of the parameterized OCSP Response against the certificate.
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

  private X509Certificate getOcspSignerFromTsl(final X509Certificate x509EeCert)
      throws GemPkiException {
    return tspServiceList.stream()
        .filter(
            tspService -> tspService.isOcspService() && tspService.containsCertificate(x509EeCert))
        .findAny()
        .orElseThrow(() -> new GemPkiException(productType, ErrorCode.SE_1030_OCSP_CERT_MISSING))
        .getFirstX509Certificate();
  }

  private X509Certificate getSignerFromOcspResponse() throws GemPkiException {
    final BasicOCSPResp basicOcspResp = getBasicOcspResp(ocspResponse);
    final X509CertificateHolder[] certs = basicOcspResp.getCerts();

    if (certs.length == 0) {
      throw new GemPkiRuntimeException("Keine Zertifikate in der OCSP-Response gefunden.");
    }

    try {
      // Check every certificate in the response
      for (final X509CertificateHolder certHolder : certs) {
        final X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certHolder);

        if (basicOcspResp.isSignatureValid(
            new JcaContentVerifierProviderBuilder().build(cert.getPublicKey()))) {
          // Found a valid signer certificate
          return cert;
        }
      }
    } catch (final CertificateException | OperatorCreationException | OCSPException e) {
      throw new GemPkiRuntimeException(
          "Fehler beim Lesen des OCSP Signer Zertifikates aus der OCSP Response.", e);
    }

    throw new GemPkiException(productType, ErrorCode.SE_1031_OCSP_SIGNATURE_ERROR);
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
    OcspVerification.verifyOcspResponseCertId(
        productType, ocspResponse, eeCert, getEeCertIssuerCert());
  }

  protected void verifyProvidedOcspResponseBasics(@NonNull final ZonedDateTime referenceDate)
      throws GemPkiException {
    OcspVerification.verifyProvidedOcspResponse(
        productType,
        ocspResponse,
        referenceDate,
        GemLibPkiUtils.now(),
        eeCert,
        getEeCertIssuerCert(),
        ocspTimeToleranceProducedAtFutureMilliseconds);
  }

  protected void verifyOcspResponseChecks(@NonNull final ZonedDateTime referenceDate)
      throws GemPkiException {
    OcspVerification.verifyStatus(productType, ocspResponse, referenceDate);
    verifyCertHash();
    OcspVerification.verifyOcspResponseAfterStatus(
        productType,
        ocspResponse,
        referenceDate,
        eeCert,
        getEeCertIssuerCert(),
        ocspTimeToleranceProducedAtPastMilliseconds,
        ocspTimeToleranceProducedAtFutureMilliseconds);
  }

  private X509Certificate getEeCertIssuerCert() throws GemPkiException {
    final TspServiceSubset tspServiceSubset =
        new TspInformationProvider(tspServiceList, productType).getIssuerTspServiceSubset(eeCert);
    return tspServiceSubset.getX509IssuerCert();
  }
}
