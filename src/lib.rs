use std::io::Cursor;
use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use std::io::Read;
use std::fmt;

const DLT_ID_SIZE: usize = 4;

const UEH_MASK: u8  = 0x01; // Bit 0: Use Extended Header
const MSBF_MASK: u8 = 0x02; // Bit 1: Most Significant Byte First
const WEID_MASK: u8 = 0x04; // Bit 2: With ECU ID
const WSID_MASK: u8 = 0x08; // Bit 3: With Session ID
const WTMS_MASK: u8 = 0x10; // Bit 4: With Timestamp
const VERS_MASK: u8 = 0xE0; // Bit 5-7: Version Number (11100000)


pub enum DLTMessageType {
    LOG,
    CONTROL,
}

impl fmt::Display for DLTMessageType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DLTMessageType::LOG => write!(f, "DLTMessageType::LOG"),
            DLTMessageType::CONTROL => write!(f, "DLTMessageType::CONTROL"),
        }
    }
}


#[derive(Debug, PartialEq)]
pub struct DltHTYP {
    UEH: bool,
    MSBF: bool, 
    WEID: bool,
    WSID: bool,
    WTMS: bool,
    VERS: u8,
}


#[derive(Debug, PartialEq)]
pub struct DltStandardHeader {
    htyp:   u8,
    mcnt:   u8,
    len:    u16,
}

#[derive(Debug, PartialEq)]
pub struct DltStandardHeaderExtra {
    ecu: [u8; DLT_ID_SIZE],
    seid: u32,
    tmsp: u32,
}

#[derive(Debug, PartialEq)]
pub struct DltExtendedHeader {
    msin: u8,
    noar: u8,
    apid: [u8; DLT_ID_SIZE],
    ctid: [u8; DLT_ID_SIZE],
}


fn dlt_standard_header_parser(cursor: &mut Cursor<&[u8]>) -> DltStandardHeader {
    //let mut cursor = Cursor::new(data);

    let htyp = cursor.read_u8().unwrap();
    let mcnt = cursor.read_u8().unwrap();
    let len = cursor.read_u16::<BigEndian>().unwrap();

    DltStandardHeader { htyp, mcnt, len }
}

fn dlt_standard_header_extra_parser(cursor: &mut Cursor<&[u8]>) -> DltStandardHeaderExtra {
    //let mut cursor = Cursor::new(data);

    let mut ecu = [0u8; DLT_ID_SIZE];
    cursor.read_exact(&mut ecu).unwrap();
    let seid = cursor.read_u32::<BigEndian>().unwrap();
    let tmsp = cursor.read_u32::<BigEndian>().unwrap();

    DltStandardHeaderExtra { ecu, seid, tmsp }
}


// { UEH: true, MSBF: false, WEID: true, WSID: true, WTMS: true, VERS: 1 }
// -> 0x3d '=' -> control message
// DltHTYP { UEH: true, MSBF: false, WEID: true, WSID: true, WTMS: true, VERS: 1 }
// -> 0x35 '5' -> log message 
pub fn dlt_analyze(x : &DltStandardHeader) -> DLTMessageType
{
    let mut ret = DLTMessageType::LOG;
    if x.get_htyp().UEH == true && x.get_htyp().MSBF == false
                                && x.get_htyp().WEID == true 
                                && x.get_htyp().WSID == true
                                && x.get_htyp().WTMS == true
                                && x.get_version() == 1
                                {
        ret = DLTMessageType::LOG;
    }else if x.get_htyp().UEH == true && x.get_htyp().MSBF == false
                                      && x.get_htyp().WEID == true 
                                      && x.get_htyp().WSID == false
                                      && x.get_htyp().WTMS == true
                                      && x.get_version() == 1
                                      {
        ret = DLTMessageType::CONTROL;
    }
    ret
}

impl DltStandardHeader {
    pub fn get_htyp(&self) -> DltHTYP {
        let UEH: bool = (self.htyp & UEH_MASK) != 0;
        let MSBF: bool = (self.htyp & MSBF_MASK) != 0;
        let WEID: bool = (self.htyp & WEID_MASK) != 0;
        let WSID: bool = (self.htyp & WSID_MASK) != 0;
        let WTMS: bool = (self.htyp & WTMS_MASK) != 0;
        let VERS: u8 = (self.htyp & VERS_MASK) >> 5;

        DltHTYP { UEH, MSBF, WEID, WSID, WTMS, VERS }
    }

    pub fn get_version(&self) -> u8 {
        let VERS: u8 = (self.htyp & VERS_MASK) >> 5;
        VERS
    }
}

impl DltStandardHeaderExtra {
    pub fn debug_print(&self){
        match std::str::from_utf8(&self.ecu) {
            Ok(ecu_str) => println!("ECU: {}", ecu_str),
            Err(e) => println!("Failed to convert ECU to string: {}", e),
        }
        println!("{}", self.seid);
        println!("{}", self.tmsp);
    }
}


// The feature image
// When you provide the binary array, you will get the splited dlt message
//  
// 
pub trait DltParse {
    fn dlt_parse(&self) -> (DltStandardHeader,
                            DltStandardHeaderExtra,
                            Vec<u8>);
}

impl DltParse for [u8] {
    fn dlt_parse(&self) -> (DltStandardHeader,
                            DltStandardHeaderExtra,
                            Vec<u8>) {
        let mut cursor = Cursor::new(self);
        let mut remaining_data: Vec<u8> = Vec::new();

        
        let dlt_standard_header = dlt_standard_header_parser(&mut cursor);
        let dlt_standard_header_extra = dlt_standard_header_extra_parser(&mut cursor);
        remaining_data.extend_from_slice(&self[cursor.position() as usize..]);                    
        

        (dlt_standard_header, dlt_standard_header_extra, remaining_data)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dlt_standard_header_extra_parser() {
        let data = [
            0x01,                   // htyp
            0x02,                   // mcnt
            0x03, 0x04,             // Length
            0x44, 0x4C, 0x54, 0x31, // ECU id: "DLT1"
            0x01, 0x00, 0x00, 0x00, // Session number: 1
            0x78, 0x56, 0x34, 0x12, // Timestamp: 0x12345678
            0x00, 0x03,             // remaining
        ];
        let (header, header_extra, remaining_data) = data.dlt_parse();

        let expected_header = DltStandardHeader {
            htyp: 0x01,
            mcnt: 0x02,
            len: 0x0403, // Note the byte order
        };

        let expected_header_extra = DltStandardHeaderExtra {
            ecu: [0x44, 0x4C, 0x54, 0x31], // "DLT1"
            seid: 1,
            tmsp: 0x12345678,
        };



        assert_eq!(header, expected_header);
        assert_eq!(header_extra, expected_header_extra);
        assert_eq!(remaining_data, [0x00, 0x03]);
    }
}
