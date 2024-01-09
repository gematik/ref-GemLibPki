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

import static de.gematik.pki.gemlibpki.utils.GemLibPkiUtils.calculateSha256;
import static de.gematik.pki.gemlibpki.utils.GemLibPkiUtils.changeLast4Bytes;
import static de.gematik.pki.gemlibpki.utils.GemLibPkiUtils.setBouncyCastleProvider;
import static org.bouncycastle.internal.asn1.isismtt.ISISMTTObjectIdentifiers.id_isismtt_at_certHash;

import com.google.common.primitives.Bytes;
import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.gemlibpki.utils.P12Container;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRespStatus;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import lombok.Builder;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.isismtt.ocsp.CertHash;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/** Class to support OCSP response generation. */
@Slf4j
@Builder
public class OcspResponseGenerator {

  static {
    setBouncyCastleProvider();
  }

  @NonNull private final P12Container signer;
  @Builder.Default private final boolean withCertHash = true;
  @Builder.Default private final boolean validCertHash = true;
  @Builder.Default private final boolean validSignature = true;

  @Builder.Default
  private final CertificateIdGeneration certificateIdGeneration =
      CertificateIdGeneration.VALID_CERTID;

  @NonNull @Builder.Default private final OCSPRespStatus respStatus = OCSPRespStatus.SUCCESSFUL;
  @Builder.Default private final boolean withResponseBytes = true;
  @NonNull @Builder.Default private final ResponderIdType responderIdType = ResponderIdType.BY_KEY;

  @NonNull @Builder.Default
  private final ZonedDateTime thisUpdate = ZonedDateTime.now(ZoneOffset.UTC);

  @NonNull @Builder.Default
  private final ZonedDateTime producedAt = ZonedDateTime.now(ZoneOffset.UTC);

  private final ZonedDateTime nextUpdate;
  @Builder.Default private final boolean withNullParameterHashAlgoOfCertId = false;

  @NonNull @Builder.Default
  private final ResponseAlgoBehavior responseAlgoBehavior = ResponseAlgoBehavior.MIRRORING;

  /** Defines options for hash algorithm to use by OCSP Responder. */
  public enum ResponseAlgoBehavior {
    /**
     * SHA1 will be used to create hashes in the OCSP response irrespective of the algorithm in the
     * OCSP request.
     */
    SHA1,

    /**
     * SHA2 (SHA256) will be used to create hashes in the OCSP response irrespective of the
     * algorithm in the OCSP request.
     */
    SHA2,

    /**
     * The same algorithm as in the OCSP request will be used to create hashes in the OCSP response.
     */
    MIRRORING
  }

  /** Defines options for modifications when generating the certificate id of the OCSP Response. */
  public enum CertificateIdGeneration {
    /** No changes to perform on elements of the certificate id when generating it. */
    VALID_CERTID,

    /** Modify serial number when generating the certificate id of the OCSP Response. */
    INVALID_CERTID_SERIAL_NUMBER,

    /** Take unsupported hash algorithm when generating the certificate id of the OCSP Response. */
    INVALID_CERTID_HASH_ALGO,

    /** Modify issuer name hash when generating the certificate id of the OCSP Response. */
    INVALID_CERTID_ISSUER_NAME_HASH,

    /** Modify issuer key hash when generating the certificate id of the OCSP Response. */
    INVALID_CERTID_ISSUER_KEY_HASH
  }

  /** Defines options for Responder Id when generating the OCSP Response. */
  public enum ResponderIdType {
    BY_KEY,
    BY_NAME
  }

  /**
   * Create OCSP response from given OCSP request. producedAt is now (UTC), with
   * certificateStatus=CertificateStatus.GOOD
   *
   * @param ocspReq OCSP request
   * @param eeCert end-entity certificate
   * @return OCSP response
   */
  public OCSPResp generate(
      @NonNull final OCSPReq ocspReq,
      @NonNull final X509Certificate eeCert,
      final X509Certificate issuerCert) {
    return generate(ocspReq, eeCert, issuerCert, CertificateStatus.GOOD);
  }

  /**
   * Create OCSP response from given OCSP request. producedAt is now (UTC).
   *
   * @param ocspReq OCSP request
   * @param eeCert end-entity certificate
   * @param certificateStatus can be null, CertificateStatus.GOOD
   * @return OCSP response
   */
  public OCSPResp generate(
      @NonNull final OCSPReq ocspReq,
      @NonNull final X509Certificate eeCert,
      @NonNull final X509Certificate issuerCert,
      final CertificateStatus certificateStatus) {

    try {
      return generate(ocspReq, eeCert, issuerCert, signer.getCertificate(), certificateStatus);
    } catch (final OperatorCreationException | IOException | OCSPException e) {
      throw new GemPkiRuntimeException("Generieren der OCSP Response fehlgeschlagen.", e);
    }
  }

  /**
   * NOTE: we copy the bouncy castle implementation, because BC does not allow other algorithms than
   * SHA1. Remove this implementation after BC update, and use {@link
   * RespID#RespID(SubjectPublicKeyInfo, DigestCalculator)}
   */
  static RespID createRespId(
      final SubjectPublicKeyInfo subjectPublicKeyInfo, final DigestCalculator digCalc) {

    try (final OutputStream digOut = digCalc.getOutputStream()) {
      digOut.write(subjectPublicKeyInfo.getPublicKeyData().getBytes());
    } catch (final IOException e) {
      throw new GemPkiRuntimeException("Generieren der RespID fehlgeschlagen.", e);
    }

    return new RespID(new ResponderID(new DEROctetString(digCalc.getDigest())));
  }

  /**
   * Create OCSP response from given OCSP request. producedAt is now (UTC).
   *
   * @param ocspReq OCSP request
   * @param ocspResponseSignerCert certificate in OCSP response signature
   * @return OCSP response
   */
  private OCSPResp generate(
      final OCSPReq ocspReq,
      final X509Certificate eeCert,
      final X509Certificate issuerCert,
      final X509Certificate ocspResponseSignerCert,
      final CertificateStatus certificateStatus)
      throws OperatorCreationException, IOException, OCSPException {

    final BasicOCSPRespBuilder basicOcspRespBuilder;

    if (responderIdType == ResponderIdType.BY_NAME) {
      final X500Principal subjectDn = ocspResponseSignerCert.getSubjectX500Principal();
      final ResponderID responderIdObj =
          new ResponderID(new X500Name(RFC4519Style.INSTANCE, subjectDn.getName()));
      basicOcspRespBuilder = new BasicOCSPRespBuilder(new RespID(responderIdObj));
    } else {
      // ResponderIdType.BY_KEY
      final DigestCalculatorProvider digCalcProv = new BcDigestCalculatorProvider();
      final byte[] publicKeyBytes = ocspResponseSignerCert.getPublicKey().getEncoded();

      final AlgorithmIdentifier algoId =
          new AlgorithmIdentifier(
              getAlgorithmForResponseAlgoBehavior(OcspUtils.getFirstSingleReq(ocspReq)));
      final AlgorithmIdentifier algorithmIdentifier = AlgorithmIdentifier.getInstance(algoId);

      final RespID respId =
          createRespId(
              SubjectPublicKeyInfo.getInstance(publicKeyBytes),
              digCalcProv.get(algorithmIdentifier));

      basicOcspRespBuilder = new BasicOCSPRespBuilder(respId);
    }

    final List<Extension> responseExtensionList = new ArrayList<>();
    addNonceExtensionIfNecessary(ocspReq, responseExtensionList);
    addCertHashExtIfNecessary(eeCert, certificateStatus, responseExtensionList);

    Extensions responseExtensions = null;
    if (!responseExtensionList.isEmpty()) {
      responseExtensions = new Extensions(responseExtensionList.toArray(Extension[]::new));
      basicOcspRespBuilder.setResponseExtensions(responseExtensions);
    }

    for (final Req singleRequest : ocspReq.getRequestList()) {
      final CertificateID certificateId = generateCertificateId(singleRequest, issuerCert);
      basicOcspRespBuilder.addResponse(
          certificateId,
          certificateStatus,
          Date.from(thisUpdate.toInstant()),
          (nextUpdate != null) ? Date.from(nextUpdate.toInstant()) : null,
          responseExtensions);
    }

    final X509CertificateHolder[] chain = {
      new X509CertificateHolder(GemLibPkiUtils.certToBytes(ocspResponseSignerCert))
    };

    final String sigAlgo =
        switch (signer.getPrivateKey().getAlgorithm()) {
          case "RSA" -> "SHA256withRSA";
          case "EC" -> "SHA256WITHECDSA";
          default -> throw new GemPkiRuntimeException(
              "Signaturalgorithmus nicht unterstützt: " + signer.getPrivateKey().getAlgorithm());
        };

    BasicOCSPResp basicOcspResp = null;

    if (withResponseBytes) {
      basicOcspResp =
          basicOcspRespBuilder.build(
              new JcaContentSignerBuilder(sigAlgo)
                  .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                  .build(signer.getPrivateKey()),
              chain,
              Date.from(producedAt.toInstant()));

      if (!validSignature) {
        log.warn(
            "OCSP response signature invalid because of user request. Parameter 'validSignature' is"
                + " set to false.");
        basicOcspResp = invalidateOcspResponseSignature(basicOcspResp);
      }
    }

    return createOcspResp(respStatus, basicOcspResp);
  }

  private void addNonceExtensionIfNecessary(
      final OCSPReq req, final List<Extension> extensionList) {
    final Extension nonceExtension = req.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
    if (nonceExtension != null) {
      extensionList.add(nonceExtension);
    }
  }

  private void addCertHashExtIfNecessary(
      final X509Certificate eeCert,
      final CertificateStatus certificateStatus,
      final List<Extension> extensionList)
      throws IOException {
    if (withCertHash) {
      if (!(certificateStatus instanceof UnknownStatus)) {
        final byte[] certificateHash;
        if (validCertHash) {
          certificateHash = calculateSha256(GemLibPkiUtils.certToBytes(eeCert));
        } else {
          log.warn(
              "Invalid CertHash is generated because of user request. Parameter 'validCertHash' is"
                  + " set to false.");
          certificateHash = calculateSha256("notAValidCertHash".getBytes(StandardCharsets.UTF_8));
        }
        final CertHash certHash =
            new CertHash(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256), certificateHash);
        extensionList.add(new Extension(id_isismtt_at_certHash, false, certHash.getEncoded()));
      } else {
        log.warn("CertHash generation disabled. Certificate status is unknown.");
      }
    } else {
      log.warn(
          "CertHash generation disabled because of user request. Parameter 'withCertHash' is set to"
              + " false.");
    }
  }

  private static OCSPResp createOcspResp(
      final OCSPRespStatus ocspRespStatus, final BasicOCSPResp basicOcspResp) throws OCSPException {

    if (basicOcspResp == null) {
      return new OCSPResp(
          new OCSPResponse(new OCSPResponseStatus(ocspRespStatus.getStatusCode()), null));
    }

    final OCSPRespBuilder ocspRespBuilder = new OCSPRespBuilder();
    return ocspRespBuilder.build(ocspRespStatus.getStatusCode(), basicOcspResp);
  }

  private static ASN1OctetString getIssuerNameHash(
      final CertificateIdGeneration certificateIdGeneration, final CertificateID certificateId) {

    final byte[] issuerNameHashBytes;
    if (certificateIdGeneration == CertificateIdGeneration.INVALID_CERTID_ISSUER_NAME_HASH) {
      issuerNameHashBytes = ArrayUtils.clone(certificateId.getIssuerNameHash());
      changeLast4Bytes(issuerNameHashBytes);
    } else {
      issuerNameHashBytes = certificateId.getIssuerNameHash();
    }
    return new DEROctetString(issuerNameHashBytes);
  }

  private static ASN1OctetString getIssuerKeyHash(
      final CertificateIdGeneration certificateIdGeneration, final CertificateID certificateId) {

    final byte[] issuerKeyHashBytes;

    if (certificateIdGeneration == CertificateIdGeneration.INVALID_CERTID_ISSUER_KEY_HASH) {
      issuerKeyHashBytes = ArrayUtils.clone(certificateId.getIssuerKeyHash());
      changeLast4Bytes(issuerKeyHashBytes);
    } else {
      issuerKeyHashBytes = certificateId.getIssuerKeyHash();
    }
    return new DEROctetString(issuerKeyHashBytes);
  }

  private static ASN1Integer getCertSerialNr(
      final CertificateIdGeneration certificateIdGeneration, final CertificateID certificateId) {
    final BigInteger certSerialNr;
    if (certificateIdGeneration == CertificateIdGeneration.INVALID_CERTID_SERIAL_NUMBER) {
      final byte[] certSerialNrBytes =
          ArrayUtils.clone(certificateId.getSerialNumber().toByteArray());
      changeLast4Bytes(certSerialNrBytes);
      certSerialNr = new BigInteger(1, certSerialNrBytes);
    } else {
      certSerialNr = certificateId.getSerialNumber();
    }
    return new ASN1Integer(certSerialNr);
  }

  /**
   * Checks if the provided algorithm is one SHA1 or SHA2 (SHA 256). If not then
   * GemPkiRuntimeException is thrown.
   *
   * @param algo the algorithm to verify
   */
  public static void verifyHashAlgoSupported(final ASN1ObjectIdentifier algo) {

    final boolean isSupported =
        algo.equals(OIWObjectIdentifiers.idSHA1) || algo.equals(NISTObjectIdentifiers.id_sha256);

    if (!isSupported) {
      throw new GemPkiRuntimeException(
          "Unknown algorithm %s. Only %s and %s are supported."
              .formatted(
                  algo.getId(),
                  OIWObjectIdentifiers.idSHA1.getId(),
                  NISTObjectIdentifiers.id_sha256.getId()));
    }
  }

  private ASN1ObjectIdentifier getAlgorithmForResponseAlgoBehavior(final Req singleRequest) {
    return switch (responseAlgoBehavior) {
      case SHA1 -> OIWObjectIdentifiers.idSHA1;
      case SHA2 -> NISTObjectIdentifiers.id_sha256;
      default -> {
        // case ResponseAlgoBehavior.MIRRORING
        final ASN1ObjectIdentifier algo = singleRequest.getCertID().getHashAlgOID();

        verifyHashAlgoSupported(algo);

        yield algo;
      }
    };
  }

  private AlgorithmIdentifier getAlgorithmIdentifier(final Req singleRequest) {

    final ASN1ObjectIdentifier asn1ObjectIdentifier;

    if (certificateIdGeneration == CertificateIdGeneration.INVALID_CERTID_HASH_ALGO) {
      asn1ObjectIdentifier = NISTObjectIdentifiers.id_sha3_512;
    } else {
      asn1ObjectIdentifier = getAlgorithmForResponseAlgoBehavior(singleRequest);
    }

    if (withNullParameterHashAlgoOfCertId) {
      return new AlgorithmIdentifier(asn1ObjectIdentifier, DERNull.INSTANCE);
    }

    return new AlgorithmIdentifier(asn1ObjectIdentifier);
  }

  private BasicOCSPResp invalidateOcspResponseSignature(final BasicOCSPResp basicOcspResp) {
    try {
      final byte[] respBytes = DSSRevocationUtils.getEncodedFromBasicResp(basicOcspResp);
      final int signatureStart = Bytes.indexOf(respBytes, basicOcspResp.getSignature());
      final int signatureEnd = signatureStart + basicOcspResp.getSignature().length;

      GemLibPkiUtils.change4Bytes(respBytes, signatureEnd);

      return DSSRevocationUtils.loadOCSPFromBinaries(respBytes);
    } catch (final IOException e) {
      throw new GemPkiRuntimeException("Fehler beim invalidieren der OCSP Response Signatur.", e);
    }
  }

  private CertificateID generateCertificateId(
      final Req singleRequest, @NonNull final X509Certificate issuerCert) {

    final AlgorithmIdentifier algorithmIdentifier = getAlgorithmIdentifier(singleRequest);

    final CertificateID computedCertificateId =
        OcspRequestGenerator.createCertificateId(
            singleRequest.getCertID().getSerialNumber(), issuerCert, algorithmIdentifier);

    final ASN1OctetString issuerNameHash =
        getIssuerNameHash(certificateIdGeneration, computedCertificateId);

    final ASN1OctetString issuerKeyHash =
        getIssuerKeyHash(certificateIdGeneration, computedCertificateId);

    final ASN1Integer certSerialNr =
        getCertSerialNr(certificateIdGeneration, computedCertificateId);

    final CertID certId =
        new CertID(algorithmIdentifier, issuerNameHash, issuerKeyHash, certSerialNr);

    return new CertificateID(certId);
  }
}
