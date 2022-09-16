/*
 * Copyright (c) 2022 gematik GmbH
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

package de.gematik.pki.gemlibpki.utils;

import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class GemlibPkiUtils {

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

  /**
   * Returns SHA256 of the input content
   *
   * @param byteArray content to generate SHA256 for
   * @return SHA256 of the input content
   */
  public static byte[] calculateSha256(final byte[] byteArray) {
    try {
      final MessageDigest digest = MessageDigest.getInstance(new SHA256Digest().getAlgorithmName());
      return digest.digest(byteArray);
    } catch (final NoSuchAlgorithmException e) {
      throw new GemPkiRuntimeException("Signaturalgorithmus nicht unterstützt.", e);
    }
  }

  /**
   * Returns SHA1 of the input content
   *
   * @param byteArray content to generate SHA1 for
   * @return SHA1 of the input content
   */
  public static byte[] calculateSha1(final byte[] byteArray) {
    try {
      final MessageDigest digest = MessageDigest.getInstance(new SHA1Digest().getAlgorithmName());
      return digest.digest(byteArray);
    } catch (final NoSuchAlgorithmException e) {
      throw new GemPkiRuntimeException("Signaturalgorithmus nicht unterstützt.", e);
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

  public static ZonedDateTime now() {
    return ZonedDateTime.now(ZoneOffset.UTC);
  }
}
