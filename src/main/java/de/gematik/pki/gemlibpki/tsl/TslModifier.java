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

package de.gematik.pki.gemlibpki.tsl;

import static de.gematik.pki.gemlibpki.tsl.TslUtils.tslDownloadUrlMatchesOid;

import eu.europa.esig.trustedlist.jaxb.tsl.AdditionalInformationType;
import eu.europa.esig.trustedlist.jaxb.tsl.AttributedNonEmptyURIType;
import eu.europa.esig.trustedlist.jaxb.tsl.MultiLangNormStringType;
import eu.europa.esig.trustedlist.jaxb.tsl.MultiLangStringType;
import eu.europa.esig.trustedlist.jaxb.tsl.NextUpdateType;
import eu.europa.esig.trustedlist.jaxb.tsl.OtherTSLPointerType;
import eu.europa.esig.trustedlist.jaxb.tsl.OtherTSLPointersType;
import eu.europa.esig.trustedlist.jaxb.tsl.ServiceSupplyPointsType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPInformationType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceInformationType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceType;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPType;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import javax.xml.bind.JAXBElement;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeConstants;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.NonNull;

/** Class for handling tsl modifications */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class TslModifier {

  /**
   * Modifies the service supply points (OCSP addresses) of a CA (PKC and SrvCertChange) entry for a
   * given TSP. Other services, such as CRL, OCSP, CVC are not altered
   *
   * @param tsl Source TSL
   * @param tspName destination TrustServiceProvider
   * @param newSsp new ServiceSupplyPoint
   */
  public static void modifySspForCAsOfTsp(
      @NonNull final TrustStatusListType tsl,
      @NonNull final String tspName,
      @NonNull final String newSsp) {

    final AttributedNonEmptyURIType newSspXml = new AttributedNonEmptyURIType();
    newSspXml.setValue(newSsp);

    final ServiceSupplyPointsType newSspType = new ServiceSupplyPointsType();
    newSspType.getServiceSupplyPoint().add(newSspXml);

    tsl.getTrustServiceProviderList()
        .getTrustServiceProvider()
        .forEach(
            tsp -> {
              final String tslTspName =
                  tsp.getTSPInformation().getTSPName().getName().get(0).getValue();

              if (tslTspName.contains(tspName)) {

                tsp.getTSPServices()
                    .getTSPService()
                    .forEach(
                        service -> {
                          final TSPServiceInformationType infoType =
                              service.getServiceInformation();
                          final String identifier = infoType.getServiceTypeIdentifier();

                          if (TslConstants.STI_CA_LIST.contains(identifier)) {
                            infoType.setServiceSupplyPoints(newSspType);
                          }
                        });
              }
            });
  }

  /**
   * Modifies the sequence number of a given tsl
   *
   * @param tsl the tsl to modify
   * @param newSeqNr the sequence number to set
   */
  public static void modifySequenceNr(@NonNull final TrustStatusListType tsl, final int newSeqNr) {
    tsl.getSchemeInformation().setTSLSequenceNumber(BigInteger.valueOf(newSeqNr));
  }

  /**
   * Modifies the nextUpdate element of the given tsl
   *
   * @param tsl The tsl to modify
   * @param zdt Utc timestamp of the new nextUpdate value
   * @throws DatatypeConfigurationException if timestamp cannot be parsed
   */
  public static void modifyNextUpdate(
      @NonNull final TrustStatusListType tsl, @NonNull final ZonedDateTime zdt)
      throws DatatypeConfigurationException {
    final XMLGregorianCalendar xmlCal = getXmlGregorianCalendar(zdt);
    final NextUpdateType nextUpdate = new NextUpdateType();
    nextUpdate.setDateTime(xmlCal);
    tsl.getSchemeInformation().setNextUpdate(nextUpdate);
  }

  /**
   * Modifies the issueDate element of the given tsl and sets the nextUpdate element according to a
   * given duration
   *
   * @param tsl The tsl to modify
   * @param issueDate Utc timestamp of the new issueDate value
   * @param daysUntilNextUpdate Integer of the duration in days the tsl will be valid
   *     (issue+duration=nextUpdate)
   * @throws DatatypeConfigurationException if timestamp cannot be parsed
   */
  public static void modifyIssueDateAndRelatedNextUpdate(
      @NonNull final TrustStatusListType tsl,
      @NonNull final ZonedDateTime issueDate,
      final int daysUntilNextUpdate)
      throws DatatypeConfigurationException {
    modifyIssueDate(tsl, issueDate);
    modifyNextUpdate(tsl, issueDate.plusDays(daysUntilNextUpdate));
  }

  /**
   * Modifies the issueDate element of the given tsl
   *
   * @param tsl The tsl to modify
   * @param zdt Utc timestamp of the nes issueDate value
   * @throws DatatypeConfigurationException if timestamp cannot be parsed
   */
  public static void modifyIssueDate(
      @NonNull final TrustStatusListType tsl, @NonNull final ZonedDateTime zdt)
      throws DatatypeConfigurationException {
    final XMLGregorianCalendar xmlCal = getXmlGregorianCalendar(zdt);
    tsl.getSchemeInformation().setListIssueDateTime(xmlCal);
  }

  /** Overwrites complete element "OtherTSLPointersType" in given TSL */
  public static void setOtherTSLPointers(
      @NonNull final TrustStatusListType tsl, @NonNull final Map<String, String> tslPointerValues) {
    final OtherTSLPointersType oTslPointers = new OtherTSLPointersType();
    final int index = 0;
    for (final Map.Entry<String, String> entry : tslPointerValues.entrySet()) {
      oTslPointers
          .getOtherTSLPointer()
          .add(index, createOtherTSLPointerType(entry.getKey(), entry.getValue()));
    }
    setElementOtherTSLPointer(tsl, oTslPointers);
  }

  /** Overwrites the primary download URL in given TSL with given URL. */
  public static void modifyTslDownloadUrlPrimary(
      @NonNull final TrustStatusListType tsl, @NonNull final String url) {
    modifyTslDownloadUrl(tsl, url, TslConstants.TSL_DOWNLOAD_URL_OID_PRIMARY);
  }

  /** Overwrites the backup download URL in given TSL with given URL. */
  public static void modifyTslDownloadUrlBackup(
      @NonNull final TrustStatusListType tsl, @NonNull final String url) {
    modifyTslDownloadUrl(tsl, url, TslConstants.TSL_DOWNLOAD_URL_OID_BACKUP);
  }

  /**
   * Generates the String for the tsl id
   *
   * @param seqNumber number of the tsl
   * @param issueDate Timestamp of the issueDate element of the tsl
   * @return New tsl id
   */
  public static String generateTslId(final int seqNumber, @NonNull final ZonedDateTime issueDate) {
    return TslConstants.TSL_ID_PREFIX
        + TslConstants.TSL_VERSION
        + seqNumber
        + issueDate.format(DateTimeFormatter.ofPattern("yyyyMMddHHmmss"))
        + issueDate.getZone();
  }

  private static void modifyTslDownloadUrl(
      final TrustStatusListType tsl, final String tslDnlUrlPrimary, final String oid) {
    tsl.getSchemeInformation().getPointersToOtherTSL().getOtherTSLPointer().stream()
        .filter(tslDownloadUrlMatchesOid(oid))
        .findFirst()
        .orElseThrow()
        .setTSLLocation(tslDnlUrlPrimary);
  }

  private static OtherTSLPointerType createOtherTSLPointerType(
      final String oid, final String tslDownloadUrl) {
    final OtherTSLPointerType otpt = new OtherTSLPointerType();
    otpt.setTSLLocation(tslDownloadUrl);

    final MultiLangStringType multiLangStringType = new MultiLangStringType();
    multiLangStringType.setLang("DE");
    multiLangStringType.setValue(oid);

    final AdditionalInformationType additionalInformationType = new AdditionalInformationType();
    additionalInformationType.getTextualInformationOrOtherInformation().add(multiLangStringType);

    otpt.setAdditionalInformation(additionalInformationType);
    return otpt;
  }

  private static void setElementOtherTSLPointer(
      final TrustStatusListType tsl, final OtherTSLPointersType otpt) {
    tsl.getSchemeInformation().setPointersToOtherTSL(otpt);
  }

  public static XMLGregorianCalendar getXmlGregorianCalendar(final ZonedDateTime zdt)
      throws DatatypeConfigurationException {
    final XMLGregorianCalendar xmlCal =
        DatatypeFactory.newInstance().newXMLGregorianCalendar(GregorianCalendar.from(zdt));
    xmlCal.setMillisecond(DatatypeConstants.FIELD_UNDEFINED);
    return xmlCal;
  }

  public static byte[] modifiedSignerCert(
      final byte[] tslBytes, final X509Certificate x509Certificate)
      throws CertificateEncodingException {
    return modifiedSignerCert(tslBytes, x509Certificate.getEncoded());
  }

  public static byte[] modifiedSignerCert(
      final byte[] tslBytes, final byte[] x509CertificateEncoded) {

    final TrustStatusListType tsl = TslConverter.bytesToTsl(tslBytes);

    modifySignerCert(tsl, x509CertificateEncoded);

    return TslConverter.tslToBytes(tsl);
  }

  public static void modifySignerCert(
      final TrustStatusListType tsl, final byte @NonNull [] x509CertificateEncoded) {

    final JAXBElement<byte[]> signatureCertificateJaxbElem =
        TslUtils.getFirstSignatureCertificateJaxbElement(tsl);

    signatureCertificateJaxbElem.setValue(x509CertificateEncoded);
  }

  /**
   * @param tslBytes tsl as a byte[]
   * @param tslId id of the tsl to modify
   * @return a new tsl with id modified
   */
  public static byte[] modifiedTslId(final byte[] tslBytes, final String tslId) {

    final TrustStatusListType tsl = TslConverter.bytesToTsl(tslBytes);

    tsl.setId(tslId);

    return TslConverter.tslToBytes(tsl);
  }

  /**
   * @param tslBytes tsl as a byte[]
   * @param seqNumber number of the tsl
   * @param issueDate Timestamp of the issueDate element of the tsl
   * @return a new tsl with id modified
   */
  public static byte[] modifiedTslId(
      final byte[] tslBytes, final int seqNumber, @NonNull final ZonedDateTime issueDate) {
    return modifiedTslId(tslBytes, generateTslId(seqNumber, issueDate));
  }

  private static List<MultiLangNormStringType> findTspTradeNames(
      final TSPType trustServiceProvider, final String tspName, final String oldTspTradeName) {

    final TSPInformationType tspInformation = trustServiceProvider.getTSPInformation();

    final String nameTspName = tspInformation.getTSPName().getName().get(0).getValue();

    final MultiLangNormStringType nameElement = tspInformation.getTSPTradeName().getName().get(0);
    final String nameTspTradeName = nameElement.getValue();

    final List<MultiLangNormStringType> selected = new ArrayList<>();
    if (tspName.equals(nameTspName) && oldTspTradeName.equals(nameTspTradeName)) {
      selected.add(nameElement);
    }

    return selected;
  }

  public static byte[] modifiedTspTradeName(
      final byte[] tslBytes,
      final String tspName,
      final String oldTspTradeName,
      final String newTspTradeName) {

    final TrustStatusListType tsl = TslConverter.bytesToTsl(tslBytes);
    modifyTspTradeName(tsl, tspName, oldTspTradeName, newTspTradeName);
    return TslConverter.tslToBytes(tsl);
  }

  public static void modifyTspTradeName(
      final TrustStatusListType tsl,
      final String tspName,
      final String oldTspTradeName,
      final String newTspTradeName) {

    final List<TSPType> trustServiceProviders =
        tsl.getTrustServiceProviderList().getTrustServiceProvider();

    for (final TSPType trustServiceProvider : trustServiceProviders) {
      final List<MultiLangNormStringType> nameElements =
          findTspTradeNames(trustServiceProvider, tspName, oldTspTradeName);

      nameElements.forEach(nameElement -> nameElement.setValue(newTspTradeName));
    }
  }

  /**
   * @param tslBytes TSL as byte[]
   * @param tspName Name of the trust service provider to change a service from
   * @param serviceIdentifierToSelect if null, then value of ServiceIdentifier is not compared
   * @param serviceStatusToSelect if null, then value of ServiceStatus is not compared
   * @param newStatusStartingTime new value for StatusStartingTime
   * @throws DatatypeConfigurationException thrown if the status starting time is in a wrong format
   */
  public static byte[] modifiedStatusStartingTime(
      final byte[] tslBytes,
      @NonNull final String tspName,
      final String serviceIdentifierToSelect,
      final String serviceStatusToSelect,
      @NonNull final ZonedDateTime newStatusStartingTime)
      throws DatatypeConfigurationException {

    final TrustStatusListType tsl = TslConverter.bytesToTsl(tslBytes);

    modifyStatusStartingTime(
        tsl, tspName, serviceIdentifierToSelect, serviceStatusToSelect, newStatusStartingTime);

    return TslConverter.tslToBytes(tsl);
  }

  /**
   * @param tsl TSL to change status starting time in
   * @param tspName Name of the trust service provider to change a service from
   * @param serviceIdentifierToSelect if null, then value of ServiceIdentifier is not compared
   * @param serviceStatusToSelect if null, then value of ServiceStatus is not compared
   * @param newStatusStartingTime new value for StatusStartingTime
   * @throws DatatypeConfigurationException thrown if the status starting time is in a wrong format
   */
  public static void modifyStatusStartingTime(
      final TrustStatusListType tsl,
      @NonNull final String tspName,
      final String serviceIdentifierToSelect,
      final String serviceStatusToSelect,
      @NonNull final ZonedDateTime newStatusStartingTime)
      throws DatatypeConfigurationException {

    final XMLGregorianCalendar newStatusStartingTimeGreg =
        TslModifier.getXmlGregorianCalendar(newStatusStartingTime);

    final List<TSPType> trustServiceProviders =
        tsl.getTrustServiceProviderList().getTrustServiceProvider();

    final Predicate<TSPServiceType> tspServicePredicate =
        tspService -> {
          final TSPServiceInformationType serviceInformation = tspService.getServiceInformation();
          final String serviceTypeIdentifier = serviceInformation.getServiceTypeIdentifier();
          final String serviceStatus = serviceInformation.getServiceStatus();

          final boolean b1 =
              (serviceIdentifierToSelect == null)
                  || serviceIdentifierToSelect.equals(serviceTypeIdentifier);

          final boolean b2 =
              (serviceStatusToSelect == null) || serviceStatusToSelect.equals(serviceStatus);

          return b1 && b2;
        };

    final List<TSPServiceType> tpsServices =
        trustServiceProviders.stream()
            .filter(
                tsp ->
                    tspName.equals(
                        tsp.getTSPInformation().getTSPName().getName().get(0).getValue()))
            .flatMap(tspType -> tspType.getTSPServices().getTSPService().stream())
            .filter(tspServicePredicate)
            .toList();

    tpsServices.forEach(
        tspService ->
            tspService.getServiceInformation().setStatusStartingTime(newStatusStartingTimeGreg));
  }
}
