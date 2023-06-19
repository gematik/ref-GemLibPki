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
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
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

  public enum CertificateIdGeneration {
    VALID_CERTID,
    INVALID_CERTID_SERIAL_NUMBER,
    INVALID_CERTID_HASH_ALGO,
    INVALID_CERTID_ISSUER_NAME_HASH,
    INVALID_CERTID_ISSUER_KEY_HASH
  }

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
  public OCSPResp generate(@NonNull final OCSPReq ocspReq, @NonNull final X509Certificate eeCert) {
    return generate(ocspReq, eeCert, CertificateStatus.GOOD);
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
      final CertificateStatus certificateStatus) {

    try {
      return generate(ocspReq, eeCert, signer.getCertificate(), certificateStatus);
    } catch (final OperatorCreationException | IOException | OCSPException e) {
      throw new GemPkiRuntimeException("Generieren der OCSP Response fehlgeschlagen.", e);
    }
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
      final X509Certificate ocspResponseSignerCert,
      final CertificateStatus certificateStatus)
      throws OperatorCreationException, IOException, OCSPException {

    final BasicOCSPRespBuilder basicOcspRespBuilder;
    switch (responderIdType) {
      case BY_NAME -> {
        final X500Principal subjectDn = ocspResponseSignerCert.getSubjectX500Principal();
        final ResponderID responderIdObj = new ResponderID(new X500Name(subjectDn.getName()));
        basicOcspRespBuilder = new BasicOCSPRespBuilder(new RespID(responderIdObj));
      }
      case BY_KEY -> {
        final DigestCalculatorProvider digCalcProv = new BcDigestCalculatorProvider();
        final byte[] publicKeyBytes = ocspResponseSignerCert.getPublicKey().getEncoded();
        basicOcspRespBuilder =
            new BasicOCSPRespBuilder(
                SubjectPublicKeyInfo.getInstance(publicKeyBytes),
                digCalcProv.get(CertificateID.HASH_SHA1));
      }
      default -> throw new GemPkiRuntimeException(
          "Fehler beim Generieren der OCSP Response: responderIdType = " + responderIdType);
    }

    final List<Extension> extensionList = new ArrayList<>();

    addCertHashExtIfNecessary(eeCert, certificateStatus, extensionList);

    final Extensions extensions = new Extensions(extensionList.toArray(Extension[]::new));
    for (final Req singleRequest : ocspReq.getRequestList()) {

      final CertificateID certificateId = generateCertificateId(singleRequest);
      basicOcspRespBuilder.addResponse(
          certificateId,
          certificateStatus,
          Date.from(thisUpdate.toInstant()),
          (nextUpdate != null) ? Date.from(nextUpdate.toInstant()) : null,
          extensions);
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
      final CertificateIdGeneration certificateIdGeneration, final Req singleRequest) {
    final byte[] issuerNameHashBytes;
    if (certificateIdGeneration == CertificateIdGeneration.INVALID_CERTID_ISSUER_NAME_HASH) {
      issuerNameHashBytes = ArrayUtils.clone(singleRequest.getCertID().getIssuerNameHash());
      changeLast4Bytes(issuerNameHashBytes);
    } else {
      issuerNameHashBytes = singleRequest.getCertID().getIssuerNameHash();
    }
    return new DEROctetString(issuerNameHashBytes);
  }

  private static ASN1OctetString getIssuerKeyHash(
      final CertificateIdGeneration certificateIdGeneration, final Req singleRequest) {

    final byte[] issuerKeyHashBytes;

    if (certificateIdGeneration == CertificateIdGeneration.INVALID_CERTID_ISSUER_KEY_HASH) {
      issuerKeyHashBytes = ArrayUtils.clone(singleRequest.getCertID().getIssuerKeyHash());
      changeLast4Bytes(issuerKeyHashBytes);
    } else {
      issuerKeyHashBytes = singleRequest.getCertID().getIssuerKeyHash();
    }
    return new DEROctetString(issuerKeyHashBytes);
  }

  private static ASN1Integer getSerialNumber(
      final CertificateIdGeneration certificateIdGeneration, final Req singleRequest) {
    final BigInteger serialNumberBigInt;
    if (certificateIdGeneration == CertificateIdGeneration.INVALID_CERTID_SERIAL_NUMBER) {
      final byte[] serialNumberBytes =
          ArrayUtils.clone(singleRequest.getCertID().getSerialNumber().toByteArray());
      changeLast4Bytes(serialNumberBytes);
      serialNumberBigInt = new BigInteger(1, serialNumberBytes);
    } else {
      serialNumberBigInt = singleRequest.getCertID().getSerialNumber();
    }
    return new ASN1Integer(serialNumberBigInt);
  }

  private AlgorithmIdentifier getAlgorithmIdentifier() {

    final ASN1ObjectIdentifier asn1ObjectIdentifier;

    if (certificateIdGeneration == CertificateIdGeneration.INVALID_CERTID_HASH_ALGO) {
      asn1ObjectIdentifier = NISTObjectIdentifiers.id_sha256;
    } else {
      asn1ObjectIdentifier = OIWObjectIdentifiers.idSHA1;
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

  private CertificateID generateCertificateId(final Req singleRequest) {

    final ASN1OctetString issuerNameHash =
        getIssuerNameHash(certificateIdGeneration, singleRequest);

    final ASN1OctetString issuerKeyHash = getIssuerKeyHash(certificateIdGeneration, singleRequest);

    final ASN1Integer serialNumber = getSerialNumber(certificateIdGeneration, singleRequest);

    final AlgorithmIdentifier algorithmIdentifier = getAlgorithmIdentifier();

    final CertID certId =
        new CertID(algorithmIdentifier, issuerNameHash, issuerKeyHash, serialNumber);

    return new CertificateID(certId);
  }
}
