use std::error::Error;

use rcgen::{CertificateParams, IsCa};
use time::OffsetDateTime;
pub fn current_time() -> Result<i64, Box<dyn Error>> {
    let time = std::time::SystemTime::now();
    let time_stamp = time.duration_since(std::time::UNIX_EPOCH)?.as_secs() as i64;
    Ok(time_stamp)
}

pub fn gen_ca() -> Result<(), Box<dyn Error>> {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.not_before = OffsetDateTime::from_unix_timestamp(current_time()?)?;
    // our certigicate is only valid for 1 year
    params.not_after = OffsetDateTime::from_unix_timestamp(current_time()? + 365 * 24 * 3600)?;
    // we just write one certigicate information
    params
        .distinguished_name
        .push(rcgen::DnType::CountryName, "China");
    // the certigicate is used for certificate inssurance
    params.key_usages.push(rcgen::KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(rcgen::KeyUsagePurpose::CrlSign);
    let key_size = rcgen::RsaKeySize::_4096;
    let key_pair = rcgen::KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, key_size)?;
    // here we get pem certificate
    let pem = params.self_signed(&key_pair)?;
    // here we get der certificate
    let der = pem.der();
    std::fs::write("sca.pem", pem.pem().as_bytes())?;
    std::fs::write("sca.der", der.to_vec().as_slice())?;
    // we only export key in PRM format,
    // while DER fomart certificates are mainly used in Windows
    std::fs::write("sca.key", key_pair.serialize_pem().as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod gen_ca_tests {
    use crate::my_cert::cert::gen_ca;

    #[test]
    fn test_gen_cert() {
        gen_ca().unwrap();
    }
}
