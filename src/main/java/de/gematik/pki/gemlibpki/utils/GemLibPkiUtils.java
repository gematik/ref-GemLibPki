/*
 * Copyright (Date see Readme), gematik GmbH
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

package de.gematik.pki.gemlibpki.utils;

import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Base64;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class GemLibPkiUtils {

  /**
   * derived from org.bouncycastle.tls.test.TlsTestUtils
   *
   * @param privateKeyEncodedStr base64 encoded string representation of a private key
   * @return {@link PrivateKey} object
   */
  public static PrivateKey convertPrivateKey(final @NonNull String privateKeyEncodedStr) {

    final byte[] privateKeyEncoded = GemLibPkiUtils.decodeFromMimeBase64(privateKeyEncodedStr);
    final PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(privateKeyEncoded);
    final AlgorithmIdentifier algoId = privateKeyInfo.getPrivateKeyAlgorithm();
    final ASN1ObjectIdentifier oid = algoId.getAlgorithm();

    final String name;
    if (X9ObjectIdentifiers.id_ecPublicKey.equals(oid)) {
      name = "EC";
    } else if (PKCSObjectIdentifiers.rsaEncryption.equals(oid)
        || PKCSObjectIdentifiers.id_RSASSA_PSS.equals(oid)) {
      name = "RSA";
    } else {
      throw new GemPkiRuntimeException(
          "Cannot create private key: unsupported algorithm - " + oid.getId());
    }

    try {
      final KeyFactory keyFactory = KeyFactory.getInstance(name);
      return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyEncoded));
    } catch (final NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new GemPkiRuntimeException(e);
    }
  }

  /**
   * Uses Files.readAllBytes(path) to read the content under the path; {@link
   * GemPkiRuntimeException} is thrown instead of {@link IOException}
   *
   * @param path the local file path
   * @return content of the file
   */
  public static byte[] readContent(final Path path) {
    try {
      return Files.readAllBytes(path);
    } catch (final IOException e) {
      throw new GemPkiRuntimeException("Cannot read path: " + path, e);
    }
  }

  public static byte[] certToBytes(@NonNull final X509Certificate certificate) {
    try {
      return certificate.getEncoded();
    } catch (final CertificateEncodingException e) {
      throw new GemPkiRuntimeException("Cannot convert certificate to bytes.", e);
    }
  }

  /**
   * Returns SHA256 of the input content
   *
   * @param byteArray content to generate SHA256 for
   * @return SHA256 of the input content
   */
  public static byte[] calculateSha256(final byte[] byteArray) {
    return calculateSha(byteArray, new SHA256Digest().getAlgorithmName());
  }

  /**
   * Returns SHA1 of the input content
   *
   * @param byteArray content to generate SHA1 for
   * @return SHA1 of the input content
   */
  public static byte[] calculateSha1(final byte[] byteArray) {
    return calculateSha(byteArray, new SHA1Digest().getAlgorithmName());
  }

  /**
   * Returns SHA1 of the input content
   *
   * @param byteArray content to generate SHA1 for
   * @param algorithmName the name of the algorithm requested
   * @return SHA1 of the input content
   */
  public static byte[] calculateSha(final byte[] byteArray, final String algorithmName) {
    try {
      final MessageDigest digest = MessageDigest.getInstance(algorithmName);
      return digest.digest(byteArray);
    } catch (final NoSuchAlgorithmException e) {
      throw new GemPkiRuntimeException(
          algorithmName + " - signaturalgorithmus nicht unterstützt.", e);
    }
  }

  /**
   * Use BouncyCastle as the security provider instead of default one and make sure that this
   * provider is at position one
   */
  public static void setBouncyCastleProvider() {
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    Security.insertProviderAt(new BouncyCastleProvider(), 1);
  }

  /**
   * Returns the current date-time from the system clock in the UTC time-zone.
   *
   * @return actual UTC date in {@link ZonedDateTime} format
   */
  public static ZonedDateTime now() {
    return ZonedDateTime.now(ZoneOffset.UTC);
  }

  public static String toMimeBase64NoLineBreaks(final X509Certificate x509Certificate) {
    return toMimeBase64NoLineBreaks(GemLibPkiUtils.certToBytes(x509Certificate));
  }

  // https://www.w3.org/TR/xmlschema-2/#base64Binary
  // RFC 2045
  public static String toMimeBase64NoLineBreaks(final byte[] bytes) {
    return Base64.getMimeEncoder(-1, new byte[0]).encodeToString(bytes);
  }

  public static byte[] decodeFromMimeBase64(final String bytesStr) {
    return Base64.getMimeDecoder().decode(bytesStr);
  }

  /**
   * Inverses bits of the last 4 byte-elements in the given array.
   *
   * @param bytes to change
   */
  public static void changeLast4Bytes(final byte[] bytes) {
    change4Bytes(bytes, bytes.length);
  }

  /**
   * Inverses bits of the 4 byte-elements before the lastIndex-th element in the given array.
   *
   * @param bytes to change
   * @param lastIndex the last index (exclusive)
   */
  public static void change4Bytes(final byte[] bytes, final int lastIndex) {
    for (int i = 1; i <= 4; i++) {
      bytes[lastIndex - i] ^= 1;
    }
  }
}
