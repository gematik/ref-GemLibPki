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

import static de.gematik.pki.gemlibpki.commons.utils.GemLibPkiUtils.setBouncyCastleProvider;

import de.gematik.pki.gemlibpki.commons.exception.GemPkiRuntimeException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import lombok.AccessLevel;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

/** Class to support OCSP related data */
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public final class OcspRequestGenerator {

  private static final int NONCE_LENGTH_BYTES = 16;
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  static {
    setBouncyCastleProvider();
  }

  public static Extension generateNonceExtension() {
    final byte[] nonceBytes = new byte[NONCE_LENGTH_BYTES];
    SECURE_RANDOM.nextBytes(nonceBytes);
    return new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, nonceBytes);
  }

  /**
   * Generates an OCSP request using BouncyCastle. SHA1 is used to compute issuer certificate's
   * hash.
   *
   * @param x509EeCert end-entity certificate
   * @param x509IssuerCert issuer of end-entity certificate
   * @return OCSP request for a single certificate
   */
  public static OCSPReq generateSingleOcspRequest(
      @NonNull final X509Certificate x509EeCert, @NonNull final X509Certificate x509IssuerCert) {
    return generateSingleOcspRequest(
        x509EeCert, x509IssuerCert, getDefaultAlgorithmIdentifier(), null);
  }

  /**
   * Generates an OCSP request and adds the given request extension if present.
   *
   * @param x509EeCert end-entity certificate
   * @param x509IssuerCert issuer of end-entity certificate
   * @param extension request extension to add
   * @return OCSP request for a single certificate
   */
  public static OCSPReq generateSingleOcspRequest(
      @NonNull final X509Certificate x509EeCert,
      @NonNull final X509Certificate x509IssuerCert,
      final Extension extension) {
    return generateSingleOcspRequest(
        x509EeCert, x509IssuerCert, getDefaultAlgorithmIdentifier(), extension);
  }

  /**
   * Creates a certificate Id from the serial number of the provided end-entity certificate and
   * issuer certificate using the specified algorithm.
   *
   * @param serialNumber the end-entity certificate whose serial number will be used
   * @param x509IssuerCert the issuer certificate
   * @param algorithmIdentifier the algorithm identifier
   * @return certificate Id
   */
  public static CertificateID createCertificateId(
      @NonNull final BigInteger serialNumber,
      @NonNull final X509Certificate x509IssuerCert,
      @NonNull final AlgorithmIdentifier algorithmIdentifier) {

    try {
      final JcaDigestCalculatorProviderBuilder digestCalculatorProviderBuilder =
          new JcaDigestCalculatorProviderBuilder();

      final DigestCalculatorProvider digestCalculatorProvider =
          digestCalculatorProviderBuilder.build();

      final DigestCalculator digestCalculator = digestCalculatorProvider.get(algorithmIdentifier);

      return new CertificateID(
          digestCalculator, new JcaX509CertificateHolder(x509IssuerCert), serialNumber);
    } catch (final OperatorCreationException | CertificateEncodingException | OCSPException e) {
      throw new GemPkiRuntimeException("Generieren der OCSP CertID fehlgeschlagen.", e);
    }
  }

  /**
   * Generates an OCSP request without nonce.
   *
   * @param x509EeCert end-entity certificate
   * @param x509IssuerCert issuer of end-entity certificate
   * @param algorithmIdentifier algorithm identifier to compute issuer certificate's hash
   * @return OCSP request for a single certificate
   */
  public static OCSPReq generateSingleOcspRequest(
      @NonNull final X509Certificate x509EeCert,
      @NonNull final X509Certificate x509IssuerCert,
      @NonNull final AlgorithmIdentifier algorithmIdentifier) {
    return generateSingleOcspRequest(x509EeCert, x509IssuerCert, algorithmIdentifier, null);
  }

  /**
   * Generates an OCSP request using BouncyCastle.
   *
   * @param x509EeCert end-entity certificate
   * @param x509IssuerCert issuer of end-entity certificate
   * @param algorithmIdentifier algorithm identifier to compute issuer certificate's hash
   * @param extension request extension to add
   * @return OCSP request for a single certificate
   */
  public static OCSPReq generateSingleOcspRequest(
      @NonNull final X509Certificate x509EeCert,
      @NonNull final X509Certificate x509IssuerCert,
      @NonNull final AlgorithmIdentifier algorithmIdentifier,
      final Extension extension) {

    try {

      final CertificateID certificateId =
          createCertificateId(x509EeCert.getSerialNumber(), x509IssuerCert, algorithmIdentifier);
      final OCSPReqBuilder ocspReqBuilder = new OCSPReqBuilder();

      ocspReqBuilder.addRequest(certificateId);
      if (extension != null) {
        ocspReqBuilder.setRequestExtensions(new Extensions(extension));
      }

      return ocspReqBuilder.build();
    } catch (final OCSPException e) {
      throw new GemPkiRuntimeException("Generieren des OCSP Requests fehlgeschlagen.", e);
    }
  }

  private static AlgorithmIdentifier getDefaultAlgorithmIdentifier() {
    return new AlgorithmIdentifier(
        OIWObjectIdentifiers.idSHA1, // NOTE this is subject to change to SHA256
        DERNull.INSTANCE);
  }
}
