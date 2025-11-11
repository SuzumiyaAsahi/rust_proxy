use rcgen::KeyUsagePurpose::{CrlSign, KeyCertSign};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, DnValue, ExtendedKeyUsagePurpose, Ia5String, IsCa,
    KeyUsagePurpose, PrintableString, SanType,
};
use std::error::Error;
use std::str::FromStr;
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
    // the certigicate is used for certificate insurance
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

// next, we need to implement certificate generation for each domain
pub fn gen_cert_for_sni(
    sni: impl AsRef<str>,
    ca: &str,
    key: &str,
) -> Result<(String, String), Box<dyn Error>> {
    let mut params = CertificateParams::default();
    //为某个SNI实现证书签发
    params
        .subject_alt_names
        .push(SanType::DnsName(Ia5String::from_str(
            sni.as_ref().to_string().as_str(),
        )?));
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.not_before = OffsetDateTime::from_unix_timestamp(current_time()?)?;
    //这里我们的根证书有效时长只有一年
    params.not_after = OffsetDateTime::from_unix_timestamp(current_time()? + 365 * 24 * 3600)?;
    //这里的证书信息至少要提供国家名和常用名
    params.distinguished_name.push(
        DnType::CountryName,
        DnValue::PrintableString(PrintableString::try_from("CN")?),
    );
    params.distinguished_name.push(
        DnType::CommonName,
        DnValue::Utf8String("Proxy-Server".to_string()),
    );
    //这里的证书用途-这个证书用途不需要，仅用于客户端认证-mtls
    //2048加速证书生成
    let key_size = rcgen::RsaKeySize::_2048;
    let key_pair = rcgen::KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, key_size)?;
    //这里我们就拿到了pem类型证书
    let ca_pem = std::fs::read_to_string(ca)?;
    let ca_key = std::fs::read_to_string(key)?;
    let key = rcgen::KeyPair::from_pem(ca_key.as_str())?;
    let ca_params = CertificateParams::from_ca_cert_pem(ca_pem.as_str())?;
    let ca = ca_params.self_signed(&key)?;
    let pem = params.signed_by(&key_pair, &ca, &key)?;
    Ok((pem.pem(), key_pair.serialize_pem()))
}

#[cfg(test)]
mod gen_ca_tests {
    use crate::my_cert::cert::{gen_ca, gen_cert_for_sni};

    #[test]
    fn test_gen_cert() {
        gen_ca().unwrap();
        let (pem, key) = gen_cert_for_sni("www.baidu.com", "sca.pem", "sca.key").unwrap();
        std::fs::write("1.pem", pem.as_bytes()).unwrap();
        std::fs::write("1.key", key.as_bytes()).unwrap();
    }
}
