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

package de.gematik.pki.gemlibpki.utils;

import static de.gematik.pki.gemlibpki.utils.GemLibPkiUtils.calculateSha1;
import static de.gematik.pki.gemlibpki.utils.GemLibPkiUtils.calculateSha256;
import static de.gematik.pki.gemlibpki.utils.TestUtils.assertNonNullParameter;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.ocsp.OcspTestConstants;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.function.BiConsumer;
import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

class GemLibPkiUtilsTest {

  @Test
  void testChangeLast4Bytes() {
    final byte[] originalBytes = {0b0, 0b0, 0b0, 0b0, 0b0, 0b0, 0b0, 0b0};
    final byte[] lastIndexArr0 = {0b0, 0b0, 0b0, 0b0, 0b1, 0b1, 0b1, 0b1};
    final byte[] lastIndexArr1 = {0b0, 0b0, 0b0, 0b1, 0b1, 0b1, 0b1, 0b0};
    final byte[] lastIndexArr2 = {0b0, 0b0, 0b1, 0b1, 0b1, 0b1, 0b0, 0b0};
    final byte[] lastIndexArr3 = {0b0, 0b1, 0b1, 0b1, 0b1, 0b0, 0b0, 0b0};
    final byte[] lastIndexArr4 = {0b1, 0b1, 0b1, 0b1, 0b0, 0b0, 0b0, 0b0};

    final BiConsumer<byte[], Integer> assertFunc =
        (arrExpected, lastIndex) -> {
          final byte[] arrActual = ArrayUtils.clone(originalBytes);
          GemLibPkiUtils.change4Bytes(arrActual, lastIndex);
          assertThat(arrActual)
              .as("change4Bytes with lastIndex = " + lastIndex)
              .isEqualTo(arrExpected);
        };

    final byte[] arrActual = ArrayUtils.clone(originalBytes);
    GemLibPkiUtils.changeLast4Bytes(arrActual);
    assertThat(arrActual).isEqualTo(lastIndexArr0);

    final int length = lastIndexArr0.length;
    assertFunc.accept(lastIndexArr0, length);
    assertFunc.accept(lastIndexArr1, length - 1);
    assertFunc.accept(lastIndexArr2, length - 2);
    assertFunc.accept(lastIndexArr3, length - 3);
    assertFunc.accept(lastIndexArr4, length - 4);
  }

  @Test
  void verifyCalculateSha1() {
    assertThat(
            new String(
                Hex.encode(calculateSha1("test".getBytes(StandardCharsets.UTF_8))),
                StandardCharsets.UTF_8))
        .isEqualTo("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3");
  }

  @Test
  void verifyCalculateShaException() {
    assertThatThrownBy(() -> GemLibPkiUtils.calculateSha(new byte[] {1, 2, 3}, "SHA-XYZ"))
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage("SHA-XYZ - signaturalgorithmus nicht unterstützt.")
        .cause()
        .isInstanceOf(NoSuchAlgorithmException.class);
  }

  @Test
  void verifyCalculateSha256() {
    assertThat(
            new String(
                Hex.encode(calculateSha256("test".getBytes(StandardCharsets.UTF_8))),
                StandardCharsets.UTF_8))
        .isEqualTo("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
  }

  @Test
  void verifyNonNulls() {
    assertNonNullParameter(() -> GemLibPkiUtils.certToBytes(null), "certificate");
    assertNonNullParameter(() -> GemLibPkiUtils.convertPrivateKey(null), "privateKeyEncodedStr");
  }

  @Test
  void testEncodeAndDecode() throws CertificateEncodingException {
    final X509Certificate eeCert =
        TestUtils.readCert("GEM.SMCB-CA10/valid/DrMedGunther_invalid-extension-not-crit.pem");

    final byte[] eeCertBytes = eeCert.getEncoded();
    final String eeCertStr = GemLibPkiUtils.toMimeBase64NoLineBreaks(eeCertBytes);

    final byte[] eeCertBytesDecoded = GemLibPkiUtils.decodeFromMimeBase64(eeCertStr);

    assertThat(eeCertBytes).isEqualTo(eeCertBytesDecoded);
    final X509Certificate eeCertDecoded = CertReader.readX509(eeCertBytesDecoded);
    assertThat(eeCertDecoded).isEqualTo(eeCert);
  }

  @Test
  void testEncodeAndDecodePrivateKeyEcc() {

    final PrivateKey privateKey = OcspTestConstants.getOcspSignerEcc().getPrivateKey();

    final byte[] privateKeyBytes = privateKey.getEncoded();
    final String privateKeyEncodedStr = GemLibPkiUtils.toMimeBase64NoLineBreaks(privateKeyBytes);

    final PrivateKey privateKeyDecoded = GemLibPkiUtils.convertPrivateKey(privateKeyEncodedStr);

    assertThat(privateKey).isEqualTo(privateKeyDecoded);
  }

  @Test
  void testEncodeAndDecodePrivateKeyRsa() {

    final PrivateKey privateKey = OcspTestConstants.getOcspSignerRsa().getPrivateKey();

    final byte[] privateKeyBytes = privateKey.getEncoded();
    final String privateKeyEncodedStr = GemLibPkiUtils.toMimeBase64NoLineBreaks(privateKeyBytes);

    final PrivateKey privateKeyDecoded = GemLibPkiUtils.convertPrivateKey(privateKeyEncodedStr);

    assertThat(privateKey).isEqualTo(privateKeyDecoded);
  }

  @Test
  void testEncodeAndDecodePrivateKeyUnknownAlgo() {

    final PrivateKey privateKey = TestUtils.readP12("ocsp/dsaCert.p12").getPrivateKey();

    final byte[] privateKeyBytes = privateKey.getEncoded();
    final String privateKeyEncodedStr = GemLibPkiUtils.toMimeBase64NoLineBreaks(privateKeyBytes);

    assertThatThrownBy(() -> GemLibPkiUtils.convertPrivateKey(privateKeyEncodedStr))
        .isInstanceOf(GemPkiRuntimeException.class)
        .hasMessage("Cannot create private key: unsupported algorithm - 1.2.840.10040.4.1"); // DSA
  }

  @Test
  void testEncodeAndDecodePrivateKeyNoSuchAlgoException() {

    final PrivateKey privateKey = OcspTestConstants.getOcspSignerEcc().getPrivateKey();

    final byte[] privateKeyBytes = privateKey.getEncoded();
    final String privateKeyEncodedStr = GemLibPkiUtils.toMimeBase64NoLineBreaks(privateKeyBytes);

    final byte[] privateKeyEncoded = GemLibPkiUtils.decodeFromMimeBase64(privateKeyEncodedStr);
    final PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(privateKeyEncoded);
    final PrivateKeyInfo privateKeyInfoMock = Mockito.spy(privateKeyInfo);

    Mockito.when(privateKeyInfoMock.getPrivateKeyAlgorithm())
        .thenReturn(new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS));

    try (final MockedStatic<KeyFactory> keyFactoryMockedStatic =
            Mockito.mockStatic(KeyFactory.class);
        final MockedStatic<PrivateKeyInfo> privateKeyInfoMockedStatic =
            Mockito.mockStatic(PrivateKeyInfo.class)) {

      privateKeyInfoMockedStatic
          .when(() -> PrivateKeyInfo.getInstance(Mockito.any()))
          .thenReturn(privateKeyInfoMock);

      keyFactoryMockedStatic
          .when(() -> KeyFactory.getInstance(Mockito.any()))
          .thenThrow(new NoSuchAlgorithmException());

      assertThatThrownBy(() -> GemLibPkiUtils.convertPrivateKey(privateKeyEncodedStr))
          .isInstanceOf(GemPkiRuntimeException.class)
          .cause()
          .isInstanceOf(NoSuchAlgorithmException.class);
    }
  }
}
