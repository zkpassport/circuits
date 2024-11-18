use std::env;
use std::fs::File;
use std::io::Read;
use prelude::der_parser::ber::BerObjectContent;
use public_key::{PublicKey, RSAPublicKey};
use x509_parser::prelude::*;
use std::io::BufReader;
use x509_parser::pem::Pem;
use std::fs::OpenOptions;
use std::io::Write;
use serde_json::{json, Value};
use der_parser;
use x509_parser::der_parser::asn1_rs::FromDer;
use x509_parser::time::ASN1Time;

extern crate noir_bignum_paramgen;
use noir_bignum_paramgen::compute_barrett_reduction_parameter;
extern crate num_bigint;
use num_bigint::BigUint;
extern crate x509_parser;
extern crate serde_json;

const OIDS_TO_DESCRIPTION: &[(&str, &str)] = &[
    ("1.2.840.113549.1.1.5", "sha1-with-rsa-signature"),
    ("1.2.840.113549.1.1.11", "sha256WithRSAEncryption"),
    ("1.2.840.113549.1.1.12", "sha384WithRSAEncryption"),
    ("1.2.840.113549.1.1.13", "sha512WithRSAEncryption"),
    ("1.2.840.113549.1.1.10", "rsassa-pss"),
    ("1.2.840.10045.4.1", "ecdsa-with-SHA1"),
    ("1.2.840.10045.4.3.2", "ecdsa-with-SHA256"),
    ("1.2.840.10045.4.3.3", "ecdsa-with-SHA384"),
    ("1.2.840.10045.4.3.4", "ecdsa-with-SHA512"),
];

fn get_oid_description(oid: &str) -> String {
    OIDS_TO_DESCRIPTION.iter().find(|&&(oid_str, _)| oid_str == oid).map(|&(_, desc)| desc.to_string()).unwrap_or_else(|| oid.to_string())
}

fn parse_certificates(cert_path: &str) -> Result<Vec<(Vec<u8>, String, Vec<u8>, String, i64, i64, usize)>, Box<dyn std::error::Error>> {
    let cert_file = File::open(cert_path)?;
    let mut reader = BufReader::new(cert_file);
    let mut results = Vec::new();

    loop {
        match Pem::read(&mut reader) {
            Ok((pem, _)) => {
                if let Ok((_, cert)) = X509Certificate::from_der(&pem.contents) {
                    let country_code = cert.issuer().iter_country()
                        .next()
                        .map(|c| c.as_str().unwrap().to_string())
                        .unwrap_or_else(|| "Unknown".to_string());

                    let not_before = cert.validity().not_before.timestamp();
                    let not_after = cert.validity().not_after.timestamp();

                    if let Ok(spki) = cert.public_key().parsed() {
                        if let PublicKey::RSA(rsa_pub_key) = spki {
                            let modulus = rsa_pub_key.modulus.to_vec();
                            let trimmed_modulus = modulus.iter()
                                .skip_while(|&&x| x == 0)
                                .copied()
                                .collect::<Vec<u8>>();
                            
                            results.push((
                                trimmed_modulus,
                                get_oid_description(&cert.signature_algorithm.algorithm.to_id_string()),
                                rsa_pub_key.exponent.to_vec(),
                                country_code,
                                not_before,
                                not_after,
                                rsa_pub_key.key_size()
                            ));
                        } else if let PublicKey::EC(ecdsa_pub_key) = spki { 
                            let params = cert.subject_pki.algorithm.parameters();   
                            if let Some(parsed_params) = params {
                                results.push((
                                    ecdsa_pub_key.data().to_vec(),
                                    get_oid_description(&cert.signature_algorithm.algorithm.to_id_string()),
                                    parsed_params.as_bytes().to_vec(),
                                    country_code,
                                    not_before,
                                    not_after,
                                    ecdsa_pub_key.key_size()
                                ));
                            }
                        }
                    }
                }
            }
            Err(_) => break,
        }
    }

    if results.is_empty() {
        return Err("No valid certificates found".into());
    }

    Ok(results)
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        println!("Usage: {} <path_to_certificates>", args[0]);
        return;
    }

    match parse_certificates(&args[1]) {
        Ok(certs) => {
            let mut certificates = Vec::new();
            
            for (pubkey, sig_algo, params, country_code, not_before, not_after, key_size) in certs.iter() {
                let big_int_pub_key = BigUint::from_bytes_be(pubkey);
                //let result = compute_barrett_reduction_parameter(&big_int_pub_key);
                //let result_bytes = result.to_bytes_be();
                
                let cert_data = json!({
                    "signature_algorithm": sig_algo,
                    "public_key": pubkey,
                    //"barrett_reduction_parameter": result_bytes,
                    "parameters": params,
                    "issuing_country": country_code,
                    "validity": {
                        "not_before": not_before,
                        "not_after": not_after
                    },
                    "key_size": key_size
                });
                
                certificates.push(cert_data);
            }

            // Sort certificates by country code
            certificates.sort_by(|a, b| {
                let country_a = a["issuing_country"].as_str().unwrap_or("");
                let country_b = b["issuing_country"].as_str().unwrap_or("");
                country_a.cmp(country_b)
            });

            let output = json!({
                "certificates": certificates
            });

            // Write to output.json file
            let file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open("csc-masterlist.json")
                .expect("Failed to create output file");

            serde_json::to_writer_pretty(file, &output)
                .expect("Failed to write JSON to file");

            println!("Results have been written to csc-masterlist.json");
        }
        Err(e) => println!("Error parsing certificates: {}", e),
    }
}
