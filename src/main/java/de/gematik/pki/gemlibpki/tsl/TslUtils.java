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

package de.gematik.pki.gemlibpki.tsl;

import static javax.xml.crypto.dsig.XMLSignature.XMLNS;

import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.utils.CertReader;
import eu.europa.esig.trustedlist.jaxb.tsl.MultiLangStringType;
import eu.europa.esig.trustedlist.jaxb.tsl.OtherTSLPointerType;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import eu.europa.esig.xmldsig.jaxb.X509DataType;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;
import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerFactory;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class TslUtils {

  public static Predicate<OtherTSLPointerType> tslDownloadUrlMatchesOid(@NonNull final String oid) {
    return p ->
        ((MultiLangStringType)
                Optional.of(p.getAdditionalInformation())
                    .orElseThrow()
                    .getTextualInformationOrOtherInformation()
                    .stream()
                    .findFirst()
                    .orElseThrow())
            .getValue()
            .equals(oid);
  }

  static DocumentBuilder createDocBuilder() throws ParserConfigurationException {
    final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
    dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
    dbf.setNamespaceAware(true); // very important
    return dbf.newDocumentBuilder();
  }

  static TransformerFactory getTransformerFactory() {
    final TransformerFactory tf = TransformerFactory.newInstance();
    tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
    tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
    return tf;
  }

  static Unmarshaller createUnmarshaller() throws JAXBException {
    final JAXBContext jaxbContext = JAXBContext.newInstance(TrustStatusListType.class);
    return jaxbContext.createUnmarshaller();
  }

  static Marshaller createMarshaller() throws JAXBException {
    final JAXBContext jaxbContext = JAXBContext.newInstance(TrustStatusListType.class);
    final Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
    // remove xml header
    jaxbMarshaller.setProperty("com.sun.xml.bind.xmlDeclaration", false);
    // set own xml header (without "standalone")
    jaxbMarshaller.setProperty(
        "com.sun.xml.bind.xmlHeaders", "<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    // no pretty print
    jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, false);
    return jaxbMarshaller;
  }

  static JAXBElement<TrustStatusListType> createJaxbElement(
      @NonNull final TrustStatusListType tslUnsigned) {
    return new JAXBElement<>(
        new QName("http://uri.etsi.org/02231/v2#", "TrustServiceStatusList"),
        TrustStatusListType.class,
        tslUnsigned);
  }

  /**
   * @param tsl TSL to get signature from
   * @return signature element of TSL
   */
  public static Element getSignature(@NonNull final Document tsl) {
    return (Element) tsl.getElementsByTagNameNS(XMLNS, "Signature").item(0);
  }

  public static X509Certificate getFirstTslSignerCertificate(final TrustStatusListType tsl) {
    final JAXBElement<byte[]> signatureCertificateJaxbElem =
        getFirstSignatureCertificateJaxbElement(tsl);
    return CertReader.readX509(signatureCertificateJaxbElem.getValue());
  }

  public static <T> JAXBElement<T> getFirstSignatureCertificateJaxbElement(
      final TrustStatusListType tsl) {
    return tsl.getSignature().getKeyInfo().getContent().stream()
        .filter(JAXBElement.class::isInstance)
        .map(JAXBElement.class::cast)
        .map(JAXBElement::getValue)
        .filter(X509DataType.class::isInstance)
        .map(X509DataType.class::cast)
        .map(X509DataType::getX509IssuerSerialOrX509SKIOrX509SubjectName)
        .flatMap(List::stream)
        .filter(JAXBElement.class::isInstance)
        .map(z -> (JAXBElement<T>) z)
        .findFirst()
        .orElseThrow(() -> new GemPkiRuntimeException("tsl without a signer certificate element"));
  }
}
