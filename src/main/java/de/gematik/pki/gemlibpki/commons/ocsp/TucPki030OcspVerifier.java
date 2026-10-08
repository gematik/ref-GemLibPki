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

import de.gematik.pki.gemlibpki.commons.error.ErrorCode;
import de.gematik.pki.gemlibpki.commons.exception.GemPkiException;
import de.gematik.pki.gemlibpki.commons.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.commons.tsl.TslConstants;
import de.gematik.pki.gemlibpki.commons.tsl.TspInformationProvider;
import de.gematik.pki.gemlibpki.commons.tsl.TspService;
import de.gematik.pki.gemlibpki.commons.tsl.TspServiceSubset;
import de.gematik.pki.gemlibpki.commons.utils.GemLibPkiUtils;
import de.gematik.pki.gemlibpki.commons.validators.QesCaQualificationValidator;
import de.gematik.pki.gemlibpki.commons.validators.SignatureValidator;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.List;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

@AllArgsConstructor(access = AccessLevel.PROTECTED)
@Builder
@Slf4j
public class TucPki030OcspVerifier {

  @NonNull protected final String productType;
  @NonNull protected final List<TspService> tspServiceListBNetzAVl;
  @NonNull protected final X509Certificate eeCert;
  @NonNull final X509Certificate eeCertIssuerCert;
  @NonNull protected final OCSPResp ocspResponse;
  protected final Extension nonce;

  @Builder.Default
  private int ocspTimeToleranceProducedAtPastMilliseconds =
      OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_PAST_MILLISECONDS;

  @Builder.Default
  private int ocspTimeToleranceProducedAtFutureMilliseconds =
      OCSP_TIME_TOLERANCE_PRODUCEDAT_DEFAULT_FUTURE_MILLISECONDS;

  public void performOcspChecks(@NonNull final ZonedDateTime referenceDate) throws GemPkiException {
    log.info("Performing OCSP checks for TucPki030...");
    final X509Certificate ocspSigner = identifyValidOcspSigner();
    verifyOcspResponseSignature(ocspSigner);
    verifyOcspResponseChecks(referenceDate);
  }

  public void performChecksForProvidedOcspResponse(@NonNull final ZonedDateTime referenceDate)
      throws GemPkiException {
    log.info("Performing OCSP checks for provided response...");
    final X509Certificate ocspSigner = identifyValidOcspSigner();
    verifyOcspResponseSignature(ocspSigner);
    verifyProvidedOcspResponseBasics(referenceDate);
  }

  protected void verifyOcspResponseSignature(final X509Certificate ocspSigner)
      throws GemPkiException {
    try {
      if (!getBasicOcspResponse().isSignatureValid(createVerifierProvider(ocspSigner))) {
        throw new GemPkiException(productType, ErrorCode.SE_1031_OCSP_SIGNATURE_ERROR);
      }
    } catch (final OCSPException | OperatorCreationException e) {
      throw new GemPkiRuntimeException(
          "Interner Fehler beim verifizieren der Ocsp Response Signatur.", e);
    }
  }

  private X509Certificate getSignerCertFromOcspResponse() throws GemPkiException {
    final BasicOCSPResp basicOcspResp = getBasicOcspResponse();
    final X509CertificateHolder[] certs = basicOcspResp.getCerts();

    if (certs.length == 0) {
      throw new GemPkiRuntimeException("Keine Zertifikate in der OCSP-Response gefunden.");
    }

    try {
      for (final X509CertificateHolder certHolder : certs) {
        final X509Certificate cert = convertToX509Certificate(certHolder);
        if (basicOcspResp.isSignatureValid(createVerifierProvider(cert))) {
          return cert;
        }
      }
    } catch (final CertificateException | OperatorCreationException | OCSPException e) {
      throw new GemPkiRuntimeException(
          "Fehler beim Lesen des OCSP Signer Zertifikates aus der OCSP Response.", e);
    }

    throw new GemPkiException(productType, ErrorCode.SE_1031_OCSP_SIGNATURE_ERROR);
  }

  private X509Certificate identifyValidOcspSigner() throws GemPkiException {
    final X509Certificate ocspSignerCert = getSignerCertFromOcspResponse();
    if (hasOcspSignerCertInBNetzAVl(ocspSignerCert)) {
      // this path is not expected, but we have to support it for now
      return ocspSignerCert;
    }

    final ZonedDateTime chainReferenceDate = getChainReferenceDate(ocspSignerCert);

    if (hasSameIssuerAsEeCertIssuer(ocspSignerCert)) {
      verifyOcspSignerCertificate(ocspSignerCert, eeCertIssuerCert, chainReferenceDate);
      return ocspSignerCert;
    }

    final TspServiceSubset ocspSignerIssuerTspServiceSubset =
        findQesCaTspServiceBNetzAVl(ocspSignerCert);

    new QesCaQualificationValidator(productType, ocspSignerIssuerTspServiceSubset)
        .validate(chainReferenceDate);

    verifyOcspSignerCertificate(
        ocspSignerCert, ocspSignerIssuerTspServiceSubset.getX509IssuerCert(), chainReferenceDate);

    return ocspSignerCert;
  }

  private void verifyOcspSignerCertificate(
      final X509Certificate ocspSignerCert,
      final X509Certificate ocspSignerIssuerCert,
      final ZonedDateTime chainReferenceDate)
      throws GemPkiException {
    new SignatureValidator(productType, ocspSignerIssuerCert)
        .validateCertificate(ocspSignerCert, chainReferenceDate);
  }

  protected ZonedDateTime getChainReferenceDate(@NonNull final X509Certificate x509EeCert) {
    return x509EeCert.getNotBefore().toInstant().atZone(ZoneOffset.UTC);
  }

  private boolean hasSameIssuerAsEeCertIssuer(final X509Certificate ocspSignerCert) {
    return ocspSignerCert
        .getIssuerX500Principal()
        .equals(eeCertIssuerCert.getSubjectX500Principal());
  }

  private boolean hasOcspSignerCertInBNetzAVl(final X509Certificate ocspSignerCert) {
    return tspServiceListBNetzAVl.stream()
        .filter(TspService::isOcspService)
        .anyMatch(tspService -> tspService.containsCertificate(ocspSignerCert));
  }

  protected TspServiceSubset findQesCaTspServiceBNetzAVl(@NonNull final X509Certificate x509EeCert)
      throws GemPkiException {
    final List<TspService> qesCaServices =
        tspServiceListBNetzAVl.stream()
            .filter(tspService -> tspService.hasServiceTypeIdentifier(TslConstants.STI_QC))
            .toList();
    return new TspInformationProvider(qesCaServices, productType)
        .getIssuerQesCaTspServiceSubset(x509EeCert);
  }

  private BasicOCSPResp getBasicOcspResponse() {
    return getBasicOcspResp(ocspResponse);
  }

  private ContentVerifierProvider createVerifierProvider(final X509Certificate certificate)
      throws OperatorCreationException {
    return new JcaContentVerifierProviderBuilder()
        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
        .build(certificate.getPublicKey());
  }

  private X509Certificate convertToX509Certificate(final X509CertificateHolder certHolder)
      throws CertificateException {
    return new JcaX509CertificateConverter().getCertificate(certHolder);
  }

  protected void verifyProvidedOcspResponseBasics(@NonNull final ZonedDateTime referenceDate)
      throws GemPkiException {
    OcspVerification.verifyNonce(productType, ocspResponse, nonce);
    OcspVerification.verifyProvidedOcspResponse(
        productType,
        ocspResponse,
        referenceDate,
        GemLibPkiUtils.now(),
        eeCert,
        eeCertIssuerCert,
        ocspTimeToleranceProducedAtFutureMilliseconds);
  }

  protected void verifyOcspResponseChecks(@NonNull final ZonedDateTime referenceDate)
      throws GemPkiException {
    OcspVerification.verifyNonce(productType, ocspResponse, nonce);
    OcspVerification.verifyOcspResponse(
        productType,
        ocspResponse,
        referenceDate,
        GemLibPkiUtils.now(),
        eeCert,
        eeCertIssuerCert,
        ocspTimeToleranceProducedAtPastMilliseconds,
        ocspTimeToleranceProducedAtFutureMilliseconds);
  }
}
