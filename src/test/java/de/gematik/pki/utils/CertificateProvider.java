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

package de.gematik.pki.utils;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URISyntaxException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.support.AnnotationConsumer;

@Slf4j
public class CertificateProvider implements ArgumentsProvider, AnnotationConsumer<VariableSource> {

    private static String certPathSwitch;
    private static final String CERTIFICATE_SUBDIR = "/certificates/GEM.SMCB-CA10/";

    @Override
    public Stream<? extends Arguments> provideArguments(final ExtensionContext extensionContext)
        throws URISyntaxException {

        return listFilesUsingFileWalkAndVisitor(
            Path.of(
                getClass()
                    .getProtectionDomain()
                    .getCodeSource()
                    .getLocation()
                    .toURI())
                + CERTIFICATE_SUBDIR + (checkCertificateFilter() ? certPathSwitch : "unknown"))
            .map(Arguments::of);
    }

    public static Stream<X509Certificate> listFilesUsingFileWalkAndVisitor(final String resourcesFolder) {
        final List<X509Certificate> fileList = new ArrayList<>();
        try {
            Files.walkFileTree(Path.of(resourcesFolder).normalize(), new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(final Path path, final BasicFileAttributes attrs) {

                    if (!Files.isDirectory(path) && checkCertificateFilter()) {
                        try {
                            log.info("add: " + path.toAbsolutePath());
                            fileList.add(getX509Certificate(path.toAbsolutePath()));
                        } catch (final IOException e) {
                            throw new RuntimeException(" : GEMLIBPKI - Test - Die Datei ist kein Zertifikat.", e);
                        }
                    }
                    return FileVisitResult.CONTINUE;

                }
            });
        } catch (final IOException io) {
            throw new UncheckedIOException(" : GEMLIBPKI - Test - Bei der Ermittlung der Testzertifikate ist ein Fehler aufgetreten.", io);
        }
        return fileList.stream();
    }

    public static X509Certificate getX509Certificate(final Path path) throws IOException {
        return CertReader.readX509(Files.readAllBytes(path));
    }

    public static X509Certificate getX509Certificate(final String path) throws IOException {
        return getX509Certificate(Path.of(path));
    }

    @Override
    public void accept(final VariableSource variableSource) {
        certPathSwitch = variableSource.value();
    }

    private static boolean checkCertificateFilter() {
        return Optional.ofNullable(certPathSwitch)
            .map(String::trim)
            .map(string -> !certPathSwitch.isEmpty())
            .orElse(false);
    }
}
