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

import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Objects;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.NonNull;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class ResourceReader {

  public static Path getFilePathFromResources(
      @NonNull final String filename, @NonNull final Class<?> clazz) {
    try {
      return Path.of(getUrlFromResources(filename, clazz).toURI());
    } catch (final URISyntaxException e) {
      throw new GemPkiRuntimeException("Error retrieving path for resource: " + filename, e);
    }
  }

  public static URL getUrlFromResources(
      @NonNull final String filename, @NonNull final Class<?> clazz) {
    try {
      return Objects.requireNonNull(clazz.getClassLoader().getResource(filename));
    } catch (final NullPointerException e) {
      throw new GemPkiRuntimeException("Error retrieving URL for resource: " + filename, e);
    }
  }

  public static byte[] getFileFromResourceAsBytes(
      @NonNull final String filename, @NonNull final Class<?> clazz) {
    try (final InputStream inputStream = clazz.getClassLoader().getResourceAsStream(filename)) {
      return Objects.requireNonNull(inputStream).readAllBytes();
    } catch (final NullPointerException | IOException e) {
      throw new GemPkiRuntimeException("Error reading resource: " + filename, e);
    }
  }

  public static String getFileFromResourceAsString(
      @NonNull final String filename, final Class<?> clazz) {
    return new String(getFileFromResourceAsBytes(filename, clazz), StandardCharsets.UTF_8);
  }
}
