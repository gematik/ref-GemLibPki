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

package de.gematik.pki.gemlibpki.certificate;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/** Enum that host {@link CertificateType} information. */
@RequiredArgsConstructor
@Getter
public enum CertificateType {
  CERT_TYPE_GSMCK_AK_AUT("C.AK.AUT", "oid_ak_aut", "1.2.276.0.76.4.79"),
  CERT_TYPE_GSMCK_NK_VPN("C.NK.VPN", "oid_nk_vpn", "1.2.276.0.76.4.80"),
  CERT_TYPE_GSMCK_SAK_AUT("C.SAK.AUT", "oid_sak_aut", "1.2.276.0.76.4.113"),
  CERT_TYPE_EGK_AUT("C.CH.AUT", "oid_egk_aut", "1.2.276.0.76.4.70"),
  CERT_TYPE_HBA_AUT("C.HP.AUT", "oid_hba_aut", "1.2.276.0.76.4.75"),
  CERT_TYPE_SMC_B_AUT("C.HCI.AUT", "oid_smc_b_aut", "1.2.276.0.76.4.77"),
  CERT_TYPE_SMC_B_ENC("C.HCI.ENC", "oid_smc_b_enc", "1.2.276.0.76.4.76"),
  CERT_TYPE_SMC_B_OSIG("C.HCI.OSIG", "oid_smc_b_osig", "1.2.276.0.76.4.78"),
  CERT_TYPE_FD_SIG("C.FD.SIG", "oid_fd_sig", "1.2.276.0.76.4.203"),
  CERT_TYPE_FD_OSIG("C.FD.OSIG", "oid_fd_osig", "1.2.276.0.76.4.283"),
  CERT_TYPE_NONE("", "", "");

  private final String name;
  private final String oidReference;
  private final String oid;
}
