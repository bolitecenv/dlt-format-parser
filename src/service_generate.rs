use crate::types::{DltStandardHeader, DltStandardHeaderExtra, DltExtendedHeader};
use crate::types::{UEH_MASK, WSID_MASK, WTMS_MASK};
use crate::{ServiceType, MSBF_MASK};

enum ServiceControlType {
    Request = 0,
    Response = 1,
}

const DLT_TYPE_LOG: u8 = 0x0;
const DLT_TYPE_APP_TRACE: u8 = 0x1;
const DLT_TYPE_NW_TRACE: u8 = 0x2;
const DLT_TYPE_CONTROL: u8 = 0x3;

const DLT_CONTROL_REQUEST: u8 = 0x1;
const DLT_CONTROL_RESPONSE: u8 = 0x2;


pub fn dlt_generate_service_get_software_version_request() -> Vec<u8> {
    let service_id: u32 = ServiceType::GetSoftwareVersion as u32;
    let service_payload = service_id.to_be_bytes();

    dlt_create_service_format(&service_payload, ServiceControlType::Request)
}

fn dlt_create_service_format(service_payload: &[u8], service_type: ServiceControlType) -> Vec<u8> {
    
    let dlt_standard_header = DltStandardHeader {
        htyp:  UEH_MASK | MSBF_MASK | WTMS_MASK, // with WTMS
        mcnt: 0,
        len: 0, // total length
    };

    let dlt_standard_header_extra = DltStandardHeaderExtra {
        ecu: *b"0000",
        seid: 0,
        tmsp: 125,
    };

    let dlt_extended_header: DltExtendedHeader = DltExtendedHeader {
        msin: generate_mstp_service(service_type),
        noar: 1,
        apid: *b"DLTD",
        ctid: *b"INTR",
    };
    
    dlt_generate_common_format(&dlt_standard_header, &dlt_standard_header_extra, &dlt_extended_header, &service_payload)
}

fn dlt_generate_common_format(dlt_standard_header: &DltStandardHeader,
                                  dlt_standard_header_extra: &DltStandardHeaderExtra,
                                  dlt_extended_header: &DltExtendedHeader,
                                  payload: &[u8]) -> Vec<u8> {
    let mut buffer = Vec::new();

    // Serialize DLT Standard Header
    buffer.extend_from_slice(&dlt_standard_header.serialize());
    
    // Serialize DLT Standard Header Extra
    buffer.extend_from_slice(&dlt_standard_header_extra.serialize(dlt_standard_header.htyp));

    // Serialize DLT Extended Header if present
    if (dlt_standard_header.htyp & UEH_MASK) != 0 {
        buffer.extend_from_slice(&dlt_extended_header.serialize());
    }

    // Append payload
    buffer.extend_from_slice(payload);

    // Update the length field in the DLT Standard Header
    let total_length = buffer.len() as u16;
    buffer[2..4].copy_from_slice(&total_length.to_be_bytes());

    buffer
}

fn generate_mstp_service(control_type: ServiceControlType) -> u8 {
    match control_type {
        ServiceControlType::Request => 
        {
            let mstp =(DLT_CONTROL_REQUEST << 4) | ((DLT_TYPE_CONTROL << 1) & 0x0F);
            mstp
        },
        ServiceControlType::Response => {
            let mstp =(DLT_CONTROL_RESPONSE << 4) | ((DLT_TYPE_CONTROL << 1) & 0x0F);
            mstp
        },
    }
}



#[cfg(test)]
mod tests {
    use crate::DltParse;

    use super::*;

    #[test]
    fn test_generate_service_get_software_version_request() {
        let service_id: u32 = ServiceType::GetSoftwareVersion as u32;
        let service_payload = service_id.to_be_bytes();

        let packet = dlt_generate_service_get_software_version_request();
        println!("Generated DLT Service Packet: {:?}", packet);
        // Basic checks
        assert!(packet.len() > 0);
        // Check if the service ID is correctly placed in the payload

        let parsed_message = packet.dlt_parse();
        match parsed_message {
            Ok((dlt_format, _)) => {
                assert_eq!(dlt_format.standard_header.htyp, UEH_MASK | MSBF_MASK | WTMS_MASK);

                assert_eq!(dlt_format.payload, service_payload); // Service ID for GetSoftwareVersion
                
                
            },
            Err(_) => panic!("Failed to parse generated DLT message"),
        }
    }
}