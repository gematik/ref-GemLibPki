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

import static de.gematik.pki.gemlibpki.tsl.TslUtils.tslDownloadUrlMatchesOid;

import de.gematik.pki.gemlibpki.exception.GemPkiException;
import de.gematik.pki.gemlibpki.exception.GemPkiRuntimeException;
import de.gematik.pki.gemlibpki.utils.GemLibPkiUtils;
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
import jakarta.xml.bind.JAXBElement;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.stream.Stream;
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

  private static Stream<TSPServiceInformationType> getCaServiceInformation(
      @NonNull final TrustStatusListType tsl, @NonNull final String tspName) {
    return tsl.getTrustServiceProviderList().getTrustServiceProvider().stream()
        .filter(
            tsp -> {
              final String tslTspName =
                  tsp.getTSPInformation().getTSPName().getName().get(0).getValue();
              return tslTspName.contains(tspName);
            })
        .flatMap(tsp -> tsp.getTSPServices().getTSPService().stream())
        .map(TSPServiceType::getServiceInformation)
        .filter(
            serviceInformation -> {
              final String identifier = serviceInformation.getServiceTypeIdentifier();
              return TslConstants.STI_CA_LIST.contains(identifier);
            });
  }

  /**
   * Deletes the service supply points (OCSP addresses) of a CA (PKC and SrvCertChange) entry for a
   * given TSP. Other services, such as CRL, OCSP, CVC are not altered
   *
   * @param tslBytes Source TSL
   * @param x509EeCert The end-entity certificate
   */
  public static byte[] deleteSspsForCAsOfEndEntity(
      final byte @NonNull [] tslBytes,
      @NonNull final X509Certificate x509EeCert,
      @NonNull final String productType)
      throws GemPkiException {

    final TrustStatusListType tsl = TslConverter.bytesToTslUnsigned(tslBytes);
    deleteSspsForCAsOfEndEntity(tsl, x509EeCert, productType);

    return TslConverter.tslUnsignedToBytes(tsl);
  }

  /**
   * Deletes the service supply points (OCSP addresses) of a CA (PKC and SrvCertChange) entry for a
   * given TSP. Other services, such as CRL, OCSP, CVC are not altered
   *
   * @param tsl Source TSL
   * @param x509EeCert The end-entity certificate
   */
  public static void deleteSspsForCAsOfEndEntity(
      @NonNull final TrustStatusListType tsl,
      @NonNull final X509Certificate x509EeCert,
      @NonNull final String productType)
      throws GemPkiException {

    final TspService tspServiceSubset =
        new TspInformationProvider(new TslInformationProvider(tsl).getTspServices(), productType)
            .getIssuerTspService(x509EeCert);

    tspServiceSubset.getTspServiceType().getServiceInformation().setServiceSupplyPoints(null);
  }

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

    getCaServiceInformation(tsl, tspName)
        .forEach(serviceInformation -> serviceInformation.setServiceSupplyPoints(newSspType));
  }

  /**
   * Modifies the sequence number of a given tsl
   *
   * @param tsl the tsl to modify
   * @param newTslSeqNr the sequence number to set
   */
  public static void modifySequenceNr(
      @NonNull final TrustStatusListType tsl, final int newTslSeqNr) {
    tsl.getSchemeInformation().setTSLSequenceNumber(BigInteger.valueOf(newTslSeqNr));
  }

  /**
   * Modifies the nextUpdate element of the given tsl
   *
   * @param tsl The tsl to modify
   * @param zdt Utc timestamp of the new nextUpdate value
   */
  public static void modifyNextUpdate(
      @NonNull final TrustStatusListType tsl, @NonNull final ZonedDateTime zdt) {
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
   */
  public static void modifyIssueDateAndRelatedNextUpdate(
      @NonNull final TrustStatusListType tsl,
      @NonNull final ZonedDateTime issueDate,
      final int daysUntilNextUpdate) {
    modifyIssueDate(tsl, issueDate);
    modifyNextUpdate(tsl, issueDate.plusDays(daysUntilNextUpdate));
  }

  /**
   * Modifies the issueDate element of the given tsl
   *
   * @param tsl The tsl to modify
   * @param zdt Utc timestamp of the nes issueDate value
   */
  public static void modifyIssueDate(
      @NonNull final TrustStatusListType tsl, @NonNull final ZonedDateTime zdt) {
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
      final TrustStatusListType tsl, final OtherTSLPointersType otherTSLPointersType) {
    tsl.getSchemeInformation().setPointersToOtherTSL(otherTSLPointersType);
  }

  /**
   * Converts an instance of ZonedDateTime to a new instance of XMLGregorianCalendar.
   *
   * @param zdt the ZonedDateTime object to convert
   * @return the new XMLGregorianCalendar object
   */
  public static XMLGregorianCalendar getXmlGregorianCalendar(@NonNull final ZonedDateTime zdt) {

    final DatatypeFactory datatypeFactory;

    try {
      datatypeFactory = DatatypeFactory.newInstance();
    } catch (final DatatypeConfigurationException e) {
      throw new GemPkiRuntimeException(e);
    }

    final XMLGregorianCalendar xmlCal =
        datatypeFactory.newXMLGregorianCalendar(GregorianCalendar.from(zdt));
    xmlCal.setMillisecond(DatatypeConstants.FIELD_UNDEFINED);

    return xmlCal;
  }

  /**
   * Creates new TSL with the signer certificate set to the new provided value.
   *
   * @param tslBytes the TSL
   * @param x509Certificate the new signed certificate
   * @return the new TSL
   */
  public static byte[] modifiedSignerCert(
      final byte[] tslBytes, final X509Certificate x509Certificate) {
    return modifiedSignerCert(tslBytes, GemLibPkiUtils.certToBytes(x509Certificate));
  }

  /**
   * Creates new TSL with the signer certificate set to the new provided value.
   *
   * @param tslBytes the TSL
   * @param x509CertificateEncoded the new signed certificate
   * @return the new TSL
   */
  public static byte[] modifiedSignerCert(
      final byte[] tslBytes, final byte[] x509CertificateEncoded) {

    final TrustStatusListType tsl = TslConverter.bytesToTslUnsigned(tslBytes);

    modifySignerCert(tsl, x509CertificateEncoded);

    return TslConverter.tslUnsignedToBytes(tsl);
  }

  /**
   * Modifies the instance of TSL - sets the signer certificate to the new provided value.
   *
   * @param tsl the TSL
   * @param x509CertificateEncoded the new signed certificate.
   */
  public static void modifySignerCert(
      final TrustStatusListType tsl, final byte @NonNull [] x509CertificateEncoded) {

    final JAXBElement<byte[]> signatureCertificateJaxbElem =
        TslUtils.getFirstSignatureCertificateJaxbElement(tsl);

    signatureCertificateJaxbElem.setValue(x509CertificateEncoded);
  }

  /**
   * Creates new TSL with the ID set to the new provided value.
   *
   * @param tslBytes tsl as a byte[]
   * @param tslId id of the tsl to modify
   * @return a new tsl with id modified
   */
  public static byte[] modifiedTslId(final byte[] tslBytes, final String tslId) {

    final TrustStatusListType tsl = TslConverter.bytesToTslUnsigned(tslBytes);

    tsl.setId(tslId);

    return TslConverter.tslUnsignedToBytes(tsl);
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

  /**
   * Creates new TSL with modified TSP(s) selected by the provided name - in the TSP(s) the specific
   * old TSP trade name is replaced by the new one.
   *
   * @param tslBytes the TSL
   * @param tspName the name of TSP(s) to select
   * @param oldTspTradeName the old TSP trade name to replace
   * @param newTspTradeName the new value of TSP trade name
   * @return the new TSL
   */
  public static byte[] modifiedTspTradeName(
      final byte[] tslBytes,
      final String tspName,
      final String oldTspTradeName,
      final String newTspTradeName) {

    final TrustStatusListType tsl = TslConverter.bytesToTslUnsigned(tslBytes);
    modifyTspTradeName(tsl, tspName, oldTspTradeName, newTspTradeName);
    return TslConverter.tslUnsignedToBytes(tsl);
  }

  /**
   * Modifies TSP(s) selected by the provided name in the TSL - in the TSP(s) the specific old TSP
   * trade name is replaced by the new one.
   *
   * @param tsl the TSL
   * @param tspName the name of TSP(s) to select
   * @param oldTspTradeName the old TSP trade name to replace
   * @param newTspTradeName the new value of TSP trade name
   */
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
   */
  public static byte[] modifiedStatusStartingTime(
      final byte[] tslBytes,
      @NonNull final String tspName,
      final String serviceIdentifierToSelect,
      final String serviceStatusToSelect,
      @NonNull final ZonedDateTime newStatusStartingTime) {

    final TrustStatusListType tsl = TslConverter.bytesToTslUnsigned(tslBytes);

    modifyStatusStartingTime(
        tsl, tspName, serviceIdentifierToSelect, serviceStatusToSelect, newStatusStartingTime);

    return TslConverter.tslUnsignedToBytes(tsl);
  }

  /**
   * @param tsl TSL to change status starting time in
   * @param tspName Name of the trust service provider to change a service from
   * @param serviceIdentifierToSelect if null, then value of ServiceIdentifier is not compared
   * @param serviceStatusToSelect if null, then value of ServiceStatus is not compared
   * @param newStatusStartingTime new value for StatusStartingTime
   */
  public static void modifyStatusStartingTime(
      final TrustStatusListType tsl,
      @NonNull final String tspName,
      final String serviceIdentifierToSelect,
      final String serviceStatusToSelect,
      @NonNull final ZonedDateTime newStatusStartingTime) {

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

  /**
   * Removes the signature element in the provided TSL.
   *
   * @param tsl the TSL
   */
  public static void deleteSignature(final TrustStatusListType tsl) {
    tsl.setSignature(null);
  }
}
