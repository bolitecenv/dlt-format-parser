use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use debug_print::debug_println;
use std::io::Cursor;
use std::io::Read;
use std::sync::Mutex;
use std::{default, fmt};

const DLT_ID_SIZE: usize = 4;

const DLT_STORAGE_HEADER_SIZE: usize = 16;
const DLT_STANDARD_HEADER_SIZE: usize = 4;
const DLT_EXTENDED_HEADER_SIZE: usize = 10;
const DLT_STANDARD_HEADER_EXTRA_SIZE: usize = 12;
const DLT_STANDARD_HEADER_EXTRA_NOSESSIONID_SIZE: usize = 8;
const DLT_PAYLOAD_HEADER_SIZE: usize = 6;

const UEH_MASK: u8 = 0x01; // Bit 0: Use Extended Header
const MSBF_MASK: u8 = 0x02; // Bit 1: Most Significant Byte First
const WEID_MASK: u8 = 0x04; // Bit 2: With ECU ID
const WSID_MASK: u8 = 0x08; // Bit 3: With Session ID
const WTMS_MASK: u8 = 0x10; // Bit 4: With Timestamp
const VERS_MASK: u8 = 0xE0; // Bit 5-7: Version Number (11100000)

static Internal_binary: Mutex<Vec<u8>> = Mutex::new(Vec::new());

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

#[derive(Debug, PartialEq, Default)]
pub struct DltStandardHeader {
    pub htyp: u8,
    pub mcnt: u8,
    pub len: u16,
}

#[derive(Debug, PartialEq, Default)]
pub struct DltStandardHeaderExtra {
    ecu: [u8; DLT_ID_SIZE],
    seid: u32,
    tmsp: u32,
}

#[derive(Debug, PartialEq, Default)]
pub struct DltStandardHeaderExtraNoSessionID {
    pub ecu: [u8; DLT_ID_SIZE],
    pub tmsp: u32,
}

#[derive(Debug, PartialEq, Default)]
pub struct DltExtendedHeader {
    pub msin: u8,
    pub noar: u8,
    pub apid: [u8; DLT_ID_SIZE],
    pub ctid: [u8; DLT_ID_SIZE],
}

#[derive(Debug)]
pub struct DltServiceMsg {
    pub service_cmd: u32,
}

#[derive(Debug)]
pub enum MstpType {
    DLT_TYPE_LOG,
    DLT_TYPE_APP_TRACE,
    DLT_TYPE_NW_TRACE,
    DLT_TYPE_CONTROL,
    Reserved(u8),
    Invalid(u8),
}

impl MstpType {
    pub fn parse(value: u8) -> MstpType {
        match (value) {
            0x0 => MstpType::DLT_TYPE_LOG,
            0x1 => MstpType::DLT_TYPE_APP_TRACE,
            0x2 => MstpType::DLT_TYPE_NW_TRACE,
            0x3 => MstpType::DLT_TYPE_CONTROL,
            0x4..7 => MstpType::Reserved(value),
            _ => MstpType::Invalid(value),
        }
    }
}

impl fmt::Display for MstpType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MstpType::DLT_TYPE_LOG => write!(f, "DLT_TYPE_LOG"),
            MstpType::DLT_TYPE_APP_TRACE => write!(f, "DLT_TYPE_APP_TRACE"),
            MstpType::DLT_TYPE_NW_TRACE => write!(f, "DLT_TYPE_NW_TRACE"),
            MstpType::DLT_TYPE_CONTROL => write!(f, "DLT_TYPE_CONTROL"),
            MstpType::Reserved(val) => write!(f, "Reserved({})", val),
            MstpType::Invalid(val) => write!(f, "Invalid({})", val),
        }
    }
}

#[derive(Debug)]
pub enum Mtin {
    Log(MtinType_DLT_LOG),
    AppTrace(MtinType_DLT_APP_TRACE),
    NwTrace(MtinType_DLT_NW_TRACE),
    Control(MtinType_DLT_CONTROL),
    Invalid,
}

#[derive(Debug)]
pub enum MtinType_DLT_LOG {
    DLT_LOG_FATAL,
    DLT_LOG_ERROR,
    DLT_LOG_WARN,
    DLT_LOG_INFO,
    DLT_LOG_DEBUG,
    DLT_LOG_VERBOSE,
    Reserved(u8),
    Invalid(u8),
}

#[derive(Debug)]
pub enum MtinType_DLT_APP_TRACE {
    DLT_TRACE_VARIABLE,
    Reserved(u8),
    Invalid(u8),
}

#[derive(Debug)]
pub enum MtinType_DLT_NW_TRACE {
    DLT_TRACE_VARIABLE,
    Reserved(u8),
    Invalid(u8),
}

#[derive(Debug)]
pub enum MtinType_DLT_CONTROL {
    DLT_CONTROL_REQUEST,
    DLT_CONTROL_RESPONSE,
    Reserved(u8),
    Invalid(u8),
}

impl MtinType_DLT_LOG {
    pub fn parse(value: u8) -> MtinType_DLT_LOG {
        match (value) {
            0x0 => MtinType_DLT_LOG::DLT_LOG_FATAL,
            0x1 => MtinType_DLT_LOG::DLT_LOG_ERROR,
            0x2 => MtinType_DLT_LOG::DLT_LOG_WARN,
            0x3 => MtinType_DLT_LOG::DLT_LOG_INFO,
            0x4 => MtinType_DLT_LOG::DLT_LOG_DEBUG,
            0x5 => MtinType_DLT_LOG::DLT_LOG_VERBOSE,
            0x6..0x7 => MtinType_DLT_LOG::Reserved(value),
            _ => MtinType_DLT_LOG::Invalid(value),
        }
    }
}

impl MtinType_DLT_APP_TRACE {
    pub fn parse(value: u8) -> MtinType_DLT_APP_TRACE {
        MtinType_DLT_APP_TRACE::Invalid(value)
    }
}

impl MtinType_DLT_NW_TRACE {
    pub fn parse(value: u8) -> MtinType_DLT_NW_TRACE {
        MtinType_DLT_NW_TRACE::Invalid(value)
    }
}

impl MtinType_DLT_CONTROL {
    pub fn parse(value: u8) -> MtinType_DLT_CONTROL {
        match (value) {
            0x1 => MtinType_DLT_CONTROL::DLT_CONTROL_REQUEST,
            0x2 => MtinType_DLT_CONTROL::DLT_CONTROL_RESPONSE,
            0x3..0x7 => MtinType_DLT_CONTROL::Reserved(value),
            _ => MtinType_DLT_CONTROL::Invalid(value),
        }
    }
}

#[derive(Debug)]
pub struct DltFormat {
    pub standard_header: DltStandardHeader,
    pub standard_header_extra: DltStandardHeaderExtra,
    pub standard_header_extra_nosession_id: DltStandardHeaderExtraNoSessionID,
    pub extended_header: DltExtendedHeader,
    pub payload_list: MessageList,
}

fn dlt_standard_header_parser(cursor: &mut Cursor<Vec<u8>>) -> DltStandardHeader {
    //let mut cursor = Cursor::new(data);

    let htyp = cursor.read_u8().unwrap();
    let mcnt = cursor.read_u8().unwrap();
    let len = cursor.read_u16::<BigEndian>().unwrap();

    DltStandardHeader { htyp, mcnt, len }
}

fn dlt_standard_header_extra_parser(cursor: &mut Cursor<Vec<u8>>) -> DltStandardHeaderExtra {
    //let mut cursor = Cursor::new(data);

    let mut ecu = [0u8; DLT_ID_SIZE];
    cursor.read_exact(&mut ecu).unwrap();
    let seid = cursor.read_u32::<BigEndian>().unwrap();
    let tmsp = cursor.read_u32::<BigEndian>().unwrap();

    DltStandardHeaderExtra { ecu, seid, tmsp }
}

fn dlt_standard_header_extra_no_session_id_parser(
    cursor: &mut Cursor<Vec<u8>>,
) -> DltStandardHeaderExtraNoSessionID {
    //let mut cursor = Cursor::new(data);

    let mut ecu = [0u8; DLT_ID_SIZE];
    cursor.read_exact(&mut ecu).unwrap();
    let tmsp = cursor.read_u32::<BigEndian>().unwrap();

    DltStandardHeaderExtraNoSessionID { ecu, tmsp }
}

fn dlt_extended_header_parser(cursor: &mut Cursor<Vec<u8>>) -> DltExtendedHeader {
    let msin = cursor.read_u8().unwrap();
    let noar = cursor.read_u8().unwrap();
    let mut apid = [0u8; DLT_ID_SIZE];
    cursor.read_exact(&mut apid).unwrap();
    let mut ctid = [0u8; DLT_ID_SIZE];
    cursor.read_exact(&mut ctid).unwrap();

    DltExtendedHeader {
        msin,
        noar,
        apid,
        ctid,
    }
}

fn dlt_payload_parser(cursor: &mut Cursor<Vec<u8>>, len: usize) -> MessageList {
    let mut payload_header = vec![0u8; 6];
    let mut payload = vec![0u8; len];

    // cursor.read_exact(&mut payload_header).unwrap();
    // cursor.read_exact(&mut payload).unwrap();

    match cursor.read_exact(&mut payload_header) {
        Ok(_) => {
            // Successfully read payload_header and payload
            debug_println!("Successfully read payload_header and payload");
        }
        Err(e) => {
            // Handle error for reading payload
            println!("Error reading payload: {}", e);
        }
    }

    match cursor.read_exact(&mut payload) {
        Ok(_) => {
            // Successfully read payload_header and payload
            debug_println!("Successfully read payload_header and payload");
        }
        Err(e) => {
            // Handle error for reading payload
            println!("Error reading payload: {}", e);
        }
    }

    let mut array: Vec<u8> = Vec::new();
    array.extend_from_slice(&payload_header);
    array.extend_from_slice(&payload);
    let message = MessageList::parse(&array, len);

    (message)
}

fn dlt_service_parser(cursor: &mut Cursor<Vec<u8>>, len: usize) -> MessageList {
    let mut payload_header = vec![0u8; 6];
    let mut payload = vec![0u8; len];

    match cursor.read_exact(&mut payload_header) {
        Ok(_) => {
            println!("Sucess");
        }
        Err(e) => {
            println!("Error {}", e);
        }
    }
    match cursor.read_exact(&mut payload) {
        Ok(_) => {
            println!("Sucess");
        }
        Err(e) => {
            println!("Error {}", e);
        }
    }

    let message = MessageList::default();
    message
}

// { UEH: true, MSBF: false, WEID: true, WSID: true, WTMS: true, VERS: 1 }
// -> 0x3d '=' -> control message
// DltHTYP { UEH: true, MSBF: false, WEID: true, WSID: true, WTMS: true, VERS: 1 }
// -> 0x35 '5' -> log message
pub fn dlt_analyze(x: &DltStandardHeader) -> DLTMessageType {
    let mut ret = DLTMessageType::LOG;
    if x.get_htyp().UEH == true
        && x.get_htyp().MSBF == false
        && x.get_htyp().WEID == true
        && x.get_htyp().WSID == true
        && x.get_htyp().WTMS == true
        && x.get_version() == 1
    {
        ret = DLTMessageType::LOG;
    } else if x.get_htyp().UEH == true
        && x.get_htyp().MSBF == false
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

        DltHTYP {
            UEH,
            MSBF,
            WEID,
            WSID,
            WTMS,
            VERS,
        }
    }

    pub fn generate_packet(&self) -> Vec<u8> {
        let mut packet = Vec::new();

        packet.extend(&self.htyp.to_le_bytes());
        packet.extend(&self.mcnt.to_le_bytes());
        packet.extend(&self.len.to_le_bytes());

        packet
    }

    pub fn get_version(&self) -> u8 {
        let VERS: u8 = (self.htyp & VERS_MASK) >> 5;
        VERS
    }
}

impl DltStandardHeaderExtra {
    pub fn get_ecu(&self) -> String {
        match std::str::from_utf8(&self.ecu) {
            Ok(ecu_str) => ecu_str.to_string(),
            Err(e) => e.to_string(),
        }
    }

    pub fn get_timestamp(&self) -> u32 {
        self.tmsp
    }

    // TODO: make switch for parameters
    pub fn generate_packet(&self) -> Vec<u8> {
        let mut packet = Vec::new();

        packet.extend_from_slice(&self.ecu);
        packet.extend(&self.seid.to_le_bytes());
        packet.extend(&self.tmsp.to_le_bytes());

        packet
    }

    pub fn debug_print(&self) {
        match std::str::from_utf8(&self.ecu) {
            Ok(ecu_str) => println!("ECU: {}", ecu_str),
            Err(e) => println!("Failed to convert ECU to string: {}", e),
        }
        println!("{}", self.seid);
        println!("{}", self.tmsp);
    }
}

impl DltExtendedHeader {
    pub fn get_apid(&self) -> String {
        match std::str::from_utf8(&self.apid) {
            Ok(str) => str.to_string(),
            Err(e) => e.to_string(),
        }
    }

    pub fn get_ctid(&self) -> String {
        match std::str::from_utf8(&self.ctid) {
            Ok(str) => str.to_string(),
            Err(e) => e.to_string(),
        }
    }

    // TODO: make switch for parameters
    pub fn generate_packet(&self) -> Vec<u8> {
        let mut packet = Vec::new();

        packet.extend(&self.msin.to_le_bytes());
        packet.extend(&self.noar.to_le_bytes());
        packet.extend_from_slice(&self.apid);
        packet.extend_from_slice(&self.ctid);

        packet
    }

    pub fn parse(&self) -> (u8, MstpType, Mtin) {
        let byte = &self.msin;
        let verb = byte & 0b00000001; // Extract bit 0
        let mstp_val = (byte & 0b00001110) >> 1; // Extract bits 1–3
        let mtin_val = (byte & 0b11110000) >> 4; // Extract bits 4–7

        let mstp = MstpType::parse(mstp_val);
        let mtin = match mstp {
            MstpType::DLT_TYPE_LOG => Mtin::Log(MtinType_DLT_LOG::parse(mtin_val)),
            MstpType::DLT_TYPE_APP_TRACE => Mtin::AppTrace(MtinType_DLT_APP_TRACE::parse(mtin_val)),
            MstpType::DLT_TYPE_NW_TRACE => Mtin::NwTrace(MtinType_DLT_NW_TRACE::parse(mtin_val)),
            MstpType::DLT_TYPE_CONTROL => Mtin::Control(MtinType_DLT_CONTROL::parse(mtin_val)),
            _ => Mtin::Invalid,
        };

        (verb, mstp, mtin)
    }
}

impl DltStandardHeaderExtraNoSessionID {
    pub fn generate_packet(&self) -> Vec<u8> {
        let mut packet = Vec::new();

        packet.extend_from_slice(&self.ecu);
        packet.extend(&self.tmsp.to_le_bytes());

        packet
    }
}

#[derive(Debug)]
enum MessageType {
    Bool,
    Signed,
    Unsigned,
    Float,
    Array,
    String,
    Raw,
    VariableInfo,
    FixedPoint,
    TraceInfo,
    Struct,
    StringCoding,
    Reserved,
}

#[derive(Debug)]
pub struct Message {
    message_type: MessageType,
    payload: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct MessageList {
    msg_list: Vec<Message>,
}

impl MessageList {
    fn parse_type(type_byte: u32) -> Option<MessageType> {
        if type_byte & 0x10 != 0 {
            return Some(MessageType::Bool);
        }
        if type_byte & 0x20 != 0 {
            return Some(MessageType::Signed);
        }
        if type_byte & 0x40 != 0 {
            return Some(MessageType::Unsigned);
        }
        if type_byte & 0x80 != 0 {
            return Some(MessageType::Float);
        }
        if type_byte & 0x100 != 0 {
            return Some(MessageType::Array);
        }
        if type_byte & 0x200 != 0 {
            return Some(MessageType::String);
        }
        if type_byte & 0x400 != 0 {
            return Some(MessageType::Raw);
        }
        if type_byte & 0x800 != 0 {
            return Some(MessageType::VariableInfo);
        }
        if type_byte & 0x1000 != 0 {
            return Some(MessageType::FixedPoint);
        }
        if type_byte & 0x2000 != 0 {
            return Some(MessageType::TraceInfo);
        }
        if type_byte & 0x4000 != 0 {
            return Some(MessageType::Struct);
        }
        if type_byte & 0x8000 != 0 {
            return Some(MessageType::StringCoding);
        }
        None
    }

    pub fn display(&self) {
        for message in &self.msg_list {
            match message.message_type {
                MessageType::String => {
                    println!("{:?}", String::from_utf8_lossy(&message.payload));
                }
                _ => {
                    println!("{:?}", message);
                }
            }
        }
    }

    pub fn get_entire_string(&self) -> String {
        let mut message_string = String::new();

        for message in &self.msg_list {
            match message.message_type {
                MessageType::String => {
                    message_string += &String::from_utf8_lossy(&message.payload);
                }
                _ => {
                    println!("TODO: {:?}", message);
                }
            }
        }

        message_string
    }

    fn parse(data: &[u8], len: usize) -> Self {
        if len < 4 {
            panic!("Data is too short");
        }

        let mut msg_list: Vec<Message> = Vec::new();
        let mut cursor = Cursor::new(data);

        while cursor.position() < len as u64 {
            let type_length = cursor.get_ref()[cursor.position() as usize] & 0x0F;
            let type_byte = cursor
                .read_u32::<LittleEndian>()
                .expect("Failed to read type byte");

            let message_type = match Self::parse_type(type_byte) {
                Some(mt) => mt,
                None => {
                    println!("Invalid message type: {}", type_byte);
                    continue;
                }
            };

            match message_type {
                MessageType::String => {
                    let string_size = cursor
                        .read_u16::<LittleEndian>()
                        .expect("Failed to read string size");

                    let mut payload = vec![0; string_size as usize];
                    cursor
                        .read_exact(&mut payload)
                        .expect("failed to read payload");
                    msg_list.push(Message {
                        message_type,
                        payload,
                    });
                }
                _ => {
                    cursor.set_position(cursor.position() + 4);
                }
            }
        }

        for m in &msg_list {
            let string = String::from_utf8_lossy(&m.payload);
        }

        Self { msg_list: msg_list }
    }
}

// The feature image
// When you provide the binary array, you will get the splited dlt message
//
//

pub trait DltParse {
    fn dlt_parse(&self) -> Vec<DltFormat>;
}

impl DltParse for [u8] {
    fn dlt_parse(&self) -> Vec<DltFormat> {
        let mut Internal_binary_ps = Internal_binary.lock().unwrap();
        Internal_binary_ps.extend(self);

        let mut dlt_response: Vec<DltFormat> = Vec::new();

        let mut cursor: Cursor<Vec<u8>> = Cursor::new(Internal_binary_ps.to_vec());
        // println!("internal len: {}", Internal_binary_ps.len());

        loop {
            if (cursor.get_ref().len() - cursor.position() as usize)
                < (DLT_STANDARD_HEADER_SIZE + DLT_STANDARD_HEADER_EXTRA_SIZE)
            {
                Internal_binary_ps.clear();
                cursor.read_to_end(&mut Internal_binary_ps).unwrap();
                // println!("internal new length : {}", Internal_binary_ps.len());
                break;
            }

            let dlt_standard_header: DltStandardHeader = dlt_standard_header_parser(&mut cursor);
            let mut dlt_standard_header_extra: DltStandardHeaderExtra = Default::default();
            let mut dlt_standard_header_extra_nosession_id: DltStandardHeaderExtraNoSessionID =
                Default::default();
            let mut payload_list;
            let mut dlt_extended_header = Default::default();

            if (dlt_standard_header.len as usize) < DLT_STANDARD_HEADER_SIZE {
                Internal_binary_ps.clear();
                //cursor.read_to_end(&mut Internal_binary_ps).unwrap();
                break;
            }

            if (cursor.get_ref().len() - cursor.position() as usize)
                < (dlt_standard_header.len as usize - DLT_STANDARD_HEADER_SIZE)
            {
                break;
            } else {
                if dlt_standard_header.get_htyp().WSID {
                    // log message
                    dlt_standard_header_extra = dlt_standard_header_extra_parser(&mut cursor);
                    dlt_extended_header = dlt_extended_header_parser(&mut cursor);
                    let payload_length = dlt_standard_header.len as usize
                        - (DLT_STANDARD_HEADER_SIZE
                            + DLT_STANDARD_HEADER_EXTRA_SIZE
                            + DLT_EXTENDED_HEADER_SIZE
                            + DLT_PAYLOAD_HEADER_SIZE);
                    payload_list = dlt_payload_parser(&mut cursor, payload_length);
                } else {
                    // trace message
                    dlt_standard_header_extra_nosession_id =
                        dlt_standard_header_extra_no_session_id_parser(&mut cursor);
                    dlt_extended_header = dlt_extended_header_parser(&mut cursor);
                    let payload_length = dlt_standard_header.len as usize
                        - (DLT_STANDARD_HEADER_SIZE
                            + DLT_STANDARD_HEADER_EXTRA_NOSESSIONID_SIZE
                            + DLT_EXTENDED_HEADER_SIZE
                            + DLT_PAYLOAD_HEADER_SIZE);
                    payload_list = dlt_payload_parser(&mut cursor, payload_length);
                    let mut tmp_vec = vec![0u8; payload_length];
                    cursor.read_exact(&mut tmp_vec);
                    println!("{:?}", tmp_vec);
                }
            }

            dlt_response.push(DltFormat {
                standard_header: dlt_standard_header,
                standard_header_extra: dlt_standard_header_extra,
                standard_header_extra_nosession_id: dlt_standard_header_extra_nosession_id,
                extended_header: dlt_extended_header,
                payload_list: payload_list,
            });
        }

        dlt_response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dlt_standard_header_extra_parser() {
        return;
        let data: [u8; 224] = [
            0x35, 0x00, 0x00, 0x20, 0x45, 0x43, 0x55, 0x31, 0x27, 0x4b, 0x60, 0x90, 0x26, 0x01,
            0x44, 0x41, 0x31, 0x00, 0x44, 0x43, 0x31, 0x00, 0x02, 0x0f, 0x00, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x00, 0x00, 0x35, 0x00, 0x00, 0x20, 0x45, 0x43, 0x55, 0x31, 0x27, 0x4b,
            0x30, 0x45, 0x26, 0x01, 0x44, 0x41, 0x31, 0x00, 0x44, 0x43, 0x31, 0x00, 0x02, 0x0f,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x3d, 0x0e, 0x00, 0x4f, 0x45, 0x43,
            0x55, 0x31, 0x00, 0x00, 0x65, 0x84, 0x27, 0x4b, 0x30, 0x45, 0x41, 0x01, 0x44, 0x4c,
            0x54, 0x44, 0x49, 0x4e, 0x54, 0x4d, 0x00, 0x02, 0x00, 0x00, 0x2f, 0x00, 0x43, 0x6c,
            0x69, 0x65, 0x6e, 0x74, 0x20, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f,
            0x6e, 0x20, 0x23, 0x37, 0x20, 0x63, 0x6c, 0x6f, 0x73, 0x65, 0x64, 0x2e, 0x20, 0x54,
            0x6f, 0x74, 0x61, 0x6c, 0x20, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x73, 0x20, 0x3a,
            0x20, 0x30, 0x00, 0x3d, 0x0f, 0x00, 0x58, 0x45, 0x43, 0x55, 0x31, 0x00, 0x00, 0x65,
            0x84, 0x27, 0x4b, 0x60, 0x91, 0x41, 0x01, 0x44, 0x4c, 0x54, 0x44, 0x49, 0x4e, 0x54,
            0x4d, 0x00, 0x02, 0x00, 0x00, 0x38, 0x00, 0x4e, 0x65, 0x77, 0x20, 0x63, 0x6c, 0x69,
            0x65, 0x6e, 0x74, 0x20, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e,
            0x20, 0x23, 0x37, 0x20, 0x65, 0x73, 0x74, 0x61, 0x62, 0x6c, 0x69, 0x73, 0x68, 0x65,
            0x64, 0x2c, 0x20, 0x54, 0x6f, 0x74, 0x61, 0x6c, 0x20, 0x43, 0x6c, 0x69, 0x65, 0x6e,
        ];

        let dlt_analyzed_data = data.dlt_parse();

        println!("{:?}", dlt_analyzed_data);

        let expected_header = DltStandardHeader {
            htyp: 61,
            mcnt: 15,
            len: 88, // Note the byte order
        };

        let expected_header_extra = DltStandardHeaderExtra {
            ecu: [0x44, 0x4C, 0x54, 0x31], // "DLT1"
            seid: 1,
            tmsp: 0x12345678,
        };

        let expected_header_extra_nosession_id = DltStandardHeaderExtraNoSessionID {
            ecu: *b"ECU1",
            tmsp: 659251344,
        };

        assert_eq!(dlt_analyzed_data[0].standard_header, expected_header);
        //assert_eq!(dlt_analyzed_data.standard_header_extra, expected_header_extra);
        assert_eq!(
            dlt_analyzed_data[0].standard_header_extra_nosession_id,
            expected_header_extra_nosession_id
        );
        // assert_eq!(remaining_data, [0x00, 0x03]);
    }

    #[test]
    fn test_dlt_paser_log() {
        let data: [u8; 88] = [
            0x3d, 0x0f, 0x00, 0x58, 0x45, 0x43, 0x55, 0x31, 0x00, 0x00, 0x65, 0x84, 0x27, 0x4b,
            0x60, 0x91, 0x41, 0x01, 0x44, 0x4c, 0x54, 0x44, 0x49, 0x4e, 0x54, 0x4d, 0x00, 0x02,
            0x00, 0x00, 0x38, 0x00, 0x4e, 0x65, 0x77, 0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74,
            0x20, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x23, 0x37,
            0x20, 0x65, 0x73, 0x74, 0x61, 0x62, 0x6c, 0x69, 0x73, 0x68, 0x65, 0x64, 0x2c, 0x20,
            0x54, 0x6f, 0x74, 0x61, 0x6c, 0x20, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x73, 0x20,
            0x3a, 0x20, 0x31, 0x00,
        ];

        let dlt_analyzed_data = data.dlt_parse();

        println!("{:?}", dlt_analyzed_data);

        let expected_header = DltStandardHeader {
            htyp: 0x3d,
            mcnt: 15,
            len: 88, // Note the byte order
        };

        let expected_header_extra = DltStandardHeaderExtra {
            ecu: *b"ECU1", // "DLT1"
            seid: 25988,
            tmsp: 659251345,
        };

        let expected_exnteded_header = DltExtendedHeader {
            msin: 65, // "DLT1"
            noar: 1,
            apid: *b"DLTD",
            ctid: *b"INTM",
        };

        let payload = *b"New client connection #7 established, Total Clients : 1\0";

        assert_eq!(dlt_analyzed_data[0].standard_header, expected_header);
        assert_eq!(
            dlt_analyzed_data[0].standard_header_extra,
            expected_header_extra
        );
        //assert_eq!(dlt_analyzed_data.standard_header_extra_nosession_id, expected_header_extra_nosession_id);
        assert_eq!(
            dlt_analyzed_data[0].extended_header,
            expected_exnteded_header
        );

        assert_eq!(dlt_analyzed_data[0].payload, payload);
    }
}
