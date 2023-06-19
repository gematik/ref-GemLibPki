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

import static de.gematik.pki.gemlibpki.ocsp.OcspUtils.getFirstSingleResp;
import static de.gematik.pki.gemlibpki.utils.TestUtils.assertNonNullParameter;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.bouncycastle.internal.asn1.isismtt.ISISMTTObjectIdentifiers.id_isismtt_at_certHash;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.ocsp.OcspResponseGenerator.CertificateIdGeneration;
import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
import de.gematik.pki.gemlibpki.utils.TestUtils;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPRespStatus;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.isismtt.ocsp.CertHash;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

class OcspResponseGeneratorTest {

  final X509Certificate VALID_X509_EE_CERT =
      TestUtils.readCert("GEM.SMCB-CA10/valid/DrMedGunther.pem");
  final X509Certificate VALID_X509_ISSUER_CERT = TestUtils.readCert("GEM.RCA1_TEST-ONLY.pem");
  final OCSPReq ocspReq =
      OcspRequestGenerator.generateSingleOcspRequest(VALID_X509_EE_CERT, VALID_X509_ISSUER_CERT);

  OcspResponseGeneratorTest() {}

  @Test
  void createRsaObject() {
    assertDoesNotThrow(
        () -> OcspResponseGenerator.builder().signer(OcspTestConstants.getOcspSignerRsa()).build());
  }

  @Test
  void createEccObject() {
    assertDoesNotThrow(
        () -> OcspResponseGenerator.builder().signer(OcspTestConstants.getOcspSignerEcc()).build());
  }

  @Test
  void useOcspResp() {
    assertDoesNotThrow(
        () ->
            writeOcspRespToFile(
                OcspResponseGenerator.builder()
                    .signer(OcspTestConstants.getOcspSignerEcc())
                    .build()
                    .generate(ocspReq, VALID_X509_EE_CERT)));
  }

  @Test
  void bouncyCastleProviderIsSet() {
    final OcspResponseGenerator generator =
        OcspResponseGenerator.builder().signer(OcspTestConstants.getOcspSignerEcc()).build();

    assertDoesNotThrow(() -> generator.generate(ocspReq, VALID_X509_EE_CERT));

    // now remove the BouncyCastleProvider
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);

    assertThatThrownBy(() -> generator.generate(ocspReq, VALID_X509_EE_CERT))
        .isInstanceOf(GemPkiRuntimeException.class)
        .cause()
        .isInstanceOf(OperatorCreationException.class)
        .hasMessage("cannot create signer: no such provider: BC")
        .cause()
        .isInstanceOf(NoSuchProviderException.class)
        .hasMessage("no such provider: BC");
    // ... and then restore the BouncyCastleProvider
    GemLibPkiUtils.setBouncyCastleProvider();
  }

  @Test
  void useOcspRespInvalidAlgo() {
    final OcspResponseGenerator ocspResp =
        OcspResponseGenerator.builder()
            .signer(Objects.requireNonNull(TestUtils.readP12("ocsp/dsaCert.p12")))
            .build();
    assertThatThrownBy(() -> ocspResp.generate(ocspReq, VALID_X509_EE_CERT))
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage("Signaturalgorithmus nicht unterstützt: DSA");
  }

  @Test
  @DisplayName("Validate CertHash valid")
  void validateCertHashValid() {

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .validCertHash(true)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT);

    final CertHash asn1CertHash =
        CertHash.getInstance(
            getFirstSingleResp(ocspResp).getExtension(id_isismtt_at_certHash).getParsedValue());

    // sha256 hash over der encoded end-entity certificate file
    final String expectedHash = "6cda0ef261c36bc05cc66e809ea1621e1dafa794a8c8a04e114e9114689d2ff7";

    assertThat(new String(Hex.encode(asn1CertHash.getCertificateHash()), StandardCharsets.UTF_8))
        .isEqualTo(expectedHash);
  }

  @Test
  @DisplayName("Validate CertHash invalid")
  void validateCertHashInvalid() {
    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .validCertHash(false)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT);

    final CertHash asn1CertHash =
        CertHash.getInstance(
            getFirstSingleResp(ocspResp).getExtension(id_isismtt_at_certHash).getParsedValue());
    assertThat(new String(Hex.encode(asn1CertHash.getCertificateHash()), StandardCharsets.UTF_8))
        .isEqualTo(
            "65785b5437ef3a7a7521ba3ac418c8b05c036eeca88e53688ff460676f5288ba"); // sha256 hash from
    // string:
    // "notAValidCertHash"
  }

  @Test
  @DisplayName("Validate CertHash missing")
  void validateCertHashMissing() throws OCSPException {
    final BasicOCSPResp ocspResp =
        (BasicOCSPResp)
            OcspResponseGenerator.builder()
                .signer(OcspTestConstants.getOcspSignerEcc())
                .withCertHash(false)
                .build()
                .generate(ocspReq, VALID_X509_EE_CERT)
                .getResponseObject();
    assertThat(ocspResp.getExtension(id_isismtt_at_certHash)).isNull();
  }

  @Test
  @DisplayName("Validate null parameters")
  void nonNullTests() {
    final OcspResponseGenerator ocspResponseGenerator =
        OcspResponseGenerator.builder().signer(OcspTestConstants.getOcspSignerEcc()).build();

    assertNonNullParameter(
        () -> ocspResponseGenerator.generate(null, VALID_X509_EE_CERT), "ocspReq");
    assertNonNullParameter(() -> ocspResponseGenerator.generate(ocspReq, null), "eeCert");

    assertNonNullParameter(
        () -> ocspResponseGenerator.generate(null, VALID_X509_EE_CERT, CertificateStatus.GOOD),
        "ocspReq");
    assertNonNullParameter(
        () -> ocspResponseGenerator.generate(ocspReq, null, CertificateStatus.GOOD), "eeCert");
  }

  @Test
  void useOcspRespStatusUnknown() {

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT, new UnknownStatus());

    assertThat(getFirstSingleResp(ocspResp).getCertStatus()).isInstanceOf(UnknownStatus.class);
  }

  @Test
  void useOcspRespCertificateStatusRevoked() {

    final ZonedDateTime revokedDate = ZonedDateTime.now(ZoneOffset.UTC);
    final int revokedReason = CRLReason.aACompromise;

    final RevokedStatus revokedStatus =
        new RevokedStatus(Date.from(revokedDate.toInstant()), revokedReason);

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT, revokedStatus);

    final CertificateStatus respStatus = getFirstSingleResp(ocspResp).getCertStatus();
    assertThat(respStatus).isInstanceOf(RevokedStatus.class);

    final RevokedStatus respRevokedStatus = (RevokedStatus) respStatus;
    assertThat(respRevokedStatus.getRevocationReason()).isEqualTo(revokedReason);

    // NOTE: equalsTo does not work because of ASN1GeneralizedTime constructor that is internally
    // called when an OCSPResp is created: milliseconds are truncated there
    assertThat(respRevokedStatus.getRevocationTime()).isCloseTo(revokedDate.toInstant(), 1000);
  }

  @ParameterizedTest
  @EnumSource(OCSPRespStatus.class)
  void useOcspRespStatusCode(final OCSPRespStatus respStatus) throws OCSPException {

    for (final boolean withResponseBytes : List.of(true, false)) {

      final OCSPResp ocspResp =
          OcspResponseGenerator.builder()
              .signer(OcspTestConstants.getOcspSignerEcc())
              .respStatus(respStatus)
              .withResponseBytes(withResponseBytes)
              .build()
              .generate(ocspReq, VALID_X509_EE_CERT);

      assertThat(ocspResp.getStatus()).isEqualTo(respStatus.getStatusCode());

      final BasicOCSPResp basicOcspResp = (BasicOCSPResp) ocspResp.getResponseObject();

      assertThat(basicOcspResp != null).isEqualTo(withResponseBytes);
    }
  }

  @Test
  void withNullParameterHashAlgoOfCertIdFalse() {

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .withNullParameterHashAlgoOfCertId(false)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT);

    final SingleResp singleResp = getFirstSingleResp(ocspResp);
    final CertID certId = singleResp.getCertID().toASN1Primitive();
    final ASN1Encodable params = certId.getHashAlgorithm().getParameters();
    assertThat(params).isNull();
  }

  @Test
  void withNullParameterHashAlgoOfCertIdTrue() {

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .withNullParameterHashAlgoOfCertId(true)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT);

    final SingleResp singleResp = getFirstSingleResp(ocspResp);
    final CertID certId = singleResp.getCertID().toASN1Primitive();

    final ASN1Encodable params = certId.getHashAlgorithm().getParameters();

    assertThat(params).isEqualTo(DERNull.INSTANCE);
  }

  @Test
  void withCertIdInvalidCertIdIssuerNameHash() {

    final Req singleRequest = ocspReq.getRequestList()[0];
    final byte[] expectedBytes = ArrayUtils.clone(singleRequest.getCertID().getIssuerNameHash());

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .certificateIdGeneration(CertificateIdGeneration.INVALID_CERTID_ISSUER_NAME_HASH)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT);

    final SingleResp singleResp = getFirstSingleResp(ocspResp);
    final CertificateID certificateId = singleResp.getCertID();

    final byte[] actualIssuerNameHashBytes = certificateId.getIssuerNameHash();

    GemLibPkiUtils.change4Bytes(expectedBytes, expectedBytes.length);

    assertThat(actualIssuerNameHashBytes).isEqualTo(expectedBytes);
  }

  @Test
  void withCertIdInvalidCertIdIssuerKeyHash() {

    final Req singleRequest = ocspReq.getRequestList()[0];
    final byte[] expectedBytes = ArrayUtils.clone(singleRequest.getCertID().getIssuerKeyHash());

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .certificateIdGeneration(CertificateIdGeneration.INVALID_CERTID_ISSUER_KEY_HASH)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT);

    final SingleResp singleResp = getFirstSingleResp(ocspResp);
    final CertificateID certificateId = singleResp.getCertID();

    final byte[] actualIssuerKeyHashBytes = certificateId.getIssuerKeyHash();

    GemLibPkiUtils.change4Bytes(expectedBytes, expectedBytes.length);

    assertThat(actualIssuerKeyHashBytes).isEqualTo(expectedBytes);
  }

  @Test
  void withCertIdInvalidCertIdSerialNumber() {

    final Req singleRequest = ocspReq.getRequestList()[0];
    final byte[] expectedBytes = singleRequest.getCertID().getSerialNumber().toByteArray();

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .certificateIdGeneration(CertificateIdGeneration.INVALID_CERTID_SERIAL_NUMBER)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT);

    final SingleResp singleResp = getFirstSingleResp(ocspResp);
    final CertID certId = singleResp.getCertID().toASN1Primitive();

    final BigInteger actualSerialNumber = certId.getSerialNumber().getValue();

    GemLibPkiUtils.change4Bytes(expectedBytes, expectedBytes.length);
    final BigInteger expectedSerialNumber = new BigInteger(1, expectedBytes);

    assertThat(actualSerialNumber).isEqualTo(expectedSerialNumber);
  }

  @Test
  void withCertIdInvalidCertIdAlgorithmIdentifier() {

    final OCSPResp ocspResp =
        OcspResponseGenerator.builder()
            .signer(OcspTestConstants.getOcspSignerEcc())
            .certificateIdGeneration(CertificateIdGeneration.INVALID_CERTID_HASH_ALGO)
            .build()
            .generate(ocspReq, VALID_X509_EE_CERT);

    final SingleResp singleResp = getFirstSingleResp(ocspResp);
    final CertID certId = singleResp.getCertID().toASN1Primitive();
    final AlgorithmIdentifier actualAlgorithmIdentifier = certId.getHashAlgorithm();

    final String actualAlgorithmId = actualAlgorithmIdentifier.getAlgorithm().getId();
    final String expectedAlgorithmId = "2.16.840.1.101.3.4.2.1"; // SHA-256

    assertThat(actualAlgorithmId).isEqualTo(expectedAlgorithmId);
  }

  private static void writeOcspRespToFile(final OCSPResp ocspResp) throws IOException {
    Files.write(TestUtils.createLogFileInTarget("ocspResponse"), ocspResp.getEncoded());
  }
}
