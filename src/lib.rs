use debug_print::{debug_println};
use std::io::Cursor;
use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use std::io::Read;
use std::{default, fmt};
use std::sync::Mutex;

const DLT_ID_SIZE: usize = 4;

const DLT_STORAGE_HEADER_SIZE: usize = 16;
const DLT_STANDARD_HEADER_SIZE: usize = 4;
const DLT_EXTENDED_HEADER_SIZE: usize = 10;
const DLT_STANDARD_HEADER_EXTRA_SIZE: usize = 12;
const DLT_STANDARD_HEADER_EXTRA_NOSESSIONID_SIZE: usize = 8;
const DLT_PAYLOAD_HEADER_SIZE: usize = 6;

const UEH_MASK: u8  = 0x01; // Bit 0: Use Extended Header
const MSBF_MASK: u8 = 0x02; // Bit 1: Most Significant Byte First
const WEID_MASK: u8 = 0x04; // Bit 2: With ECU ID
const WSID_MASK: u8 = 0x08; // Bit 3: With Session ID
const WTMS_MASK: u8 = 0x10; // Bit 4: With Timestamp
const VERS_MASK: u8 = 0xE0; // Bit 5-7: Version Number (11100000)


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
    pub htyp:   u8,
    pub mcnt:   u8,
    pub len:    u16,
}

#[derive(Debug, PartialEq, Default)]
pub struct DltStandardHeaderExtra {
    ecu: [u8; DLT_ID_SIZE],
    seid: u32,
    tmsp: u32,
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
    pub service_cmd: u32
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
pub enum MtinType_DLT_LOG{
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
            0x6.. 0x7 => MtinType_DLT_LOG::Reserved(value),
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
            0x3.. 0x7 => MtinType_DLT_CONTROL::Reserved(value),
            _ => MtinType_DLT_CONTROL::Invalid(value),
        }
    }
}

#[derive(Debug)]
pub struct DltFormat{
    pub standard_header: DltStandardHeader,
    pub standard_header_extra: DltStandardHeaderExtra,
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

fn dlt_standard_header_extra_parser(htyp: &DltHTYP, cursor: &mut Cursor<Vec<u8>>) -> DltStandardHeaderExtra {
    let mut ecu = [0u8; DLT_ID_SIZE];
    let mut seid: u32 = 0;
    let mut tmsp: u32 = 0;

    if htyp.WEID {
        cursor.read_exact(&mut ecu).unwrap();
    }

    if htyp.WSID {
        seid = cursor.read_u32::<BigEndian>().unwrap();
    }

    if htyp.WTMS {
        tmsp = cursor.read_u32::<BigEndian>().unwrap();
    }

    DltStandardHeaderExtra { ecu, seid, tmsp }
}

fn dlt_extended_header_parser(htyp: &DltHTYP , cursor: &mut Cursor<Vec<u8>>) -> DltExtendedHeader {
    if !htyp.UEH {
        return DltExtendedHeader::default();
    }

    let msin = cursor.read_u8().unwrap();
    let noar = cursor.read_u8().unwrap();
    let mut apid = [0u8; DLT_ID_SIZE];
    cursor.read_exact(&mut apid).unwrap();
    let mut ctid = [0u8; DLT_ID_SIZE];
    cursor.read_exact(&mut ctid).unwrap();

    DltExtendedHeader { msin, noar, apid, ctid }
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

fn dlt_standard_header_size() -> usize {
    DLT_STANDARD_HEADER_SIZE
}

fn dlt_standard_header_extra_size(htyp: &DltHTYP) -> usize {
    let mut size = 0;

    if htyp.WEID {
        size += DLT_ID_SIZE;
    }
    if htyp.WSID {
        size += 4;
    }
    if htyp.WTMS {
        size += 4;
    }

    size
}

fn dlt_extended_header_size(htyp: &DltHTYP) -> usize {
    if !htyp.UEH {
        0
    } else {
        DLT_EXTENDED_HEADER_SIZE
    }
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
    pub fn get_ecu(&self) -> String{
        match std::str::from_utf8(&self.ecu) {
            Ok(ecu_str) => ecu_str.to_string(),
            Err(e) => e.to_string(),
        }
    }

    pub fn get_timestamp(&self) -> u32{
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

    pub fn debug_print(&self){
        match std::str::from_utf8(&self.ecu) {
            Ok(ecu_str) => println!("ECU: {}", ecu_str),
            Err(e) => println!("Failed to convert ECU to string: {}", e),
        }
        println!("{}", self.seid);
        println!("{}", self.tmsp);
    }
}

impl DltExtendedHeader{
    pub fn get_apid(&self) -> String{
        match std::str::from_utf8(&self.apid) {
            Ok(str) => str.to_string(),
            Err(e) => e.to_string(),
        }
    }

    pub fn get_ctid(&self) -> String{
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
        let verb = byte & 0b00000001;               // Extract bit 0
        let mstp_val = (byte & 0b00001110) >> 1;        // Extract bits 1–3
        let mtin_val = (byte & 0b11110000) >> 4;        // Extract bits 4–7

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
        if type_byte & 0x10 != 0 {return Some(MessageType::Bool); }
        if type_byte & 0x20 != 0 {return Some(MessageType::Signed); }
        if type_byte & 0x40 != 0 {return Some(MessageType::Unsigned); }
        if type_byte & 0x80 != 0 {return Some(MessageType::Float); }
        if type_byte & 0x100 != 0 {return Some(MessageType::Array); }
        if type_byte & 0x200 != 0 {return Some(MessageType::String); }
        if type_byte & 0x400 != 0 {return Some(MessageType::Raw); }
        if type_byte & 0x800 != 0 {return Some(MessageType::VariableInfo); }
        if type_byte & 0x1000 != 0 {return Some(MessageType::FixedPoint); }
        if type_byte & 0x2000 != 0 {return Some(MessageType::TraceInfo); }
        if type_byte & 0x4000 != 0 {return Some(MessageType::Struct); }
        if type_byte & 0x8000 != 0 {return Some(MessageType::StringCoding); }
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
            println!("Data is too short: {} bytes", len);
            return Self::default();
        }

        let mut msg_list: Vec<Message> = Vec::new();
        let mut cursor = Cursor::new(data.to_vec());

        println!("Starting to parse payload of {} bytes", len);

        while cursor.position() < len as u64 {
            println!("Current position: {}, remaining: {}", cursor.position(), len as u64 - cursor.position());
            
            // FIXED: Read the type info correctly
            if cursor.position() + 4 > len as u64 {
                println!("Not enough bytes for type header");
                break;
            }
            
            let type_byte = cursor.read_u32::<LittleEndian>().expect("Failed to read type byte");
            println!("Type byte: 0x{:08X}", type_byte);

            // FIXED: Extract type length from the first byte
            let type_length = (type_byte & 0x0F) as u8;
            println!("Type length field: {}", type_length);

            let message_type = match Self::parse_type(type_byte) {
                Some(mt) => mt,
                None => {
                    println!("Invalid message type: 0x{:08X}", type_byte);
                    break;
                }
            };

            println!("Detected message type: {:?}", message_type);

            match message_type {
                MessageType::Bool => {
                    // FIXED: Use appropriate size calculation
                    let bool_size = if type_length > 0 { type_length as usize } else { 1 };
                    
                    if cursor.position() + bool_size as u64 > len as u64 {
                        println!("Not enough bytes for bool payload");
                        break;
                    }

                    let mut payload = vec![0; bool_size];
                    cursor.read_exact(&mut payload).expect("failed to read payload");
                    msg_list.push(Message {
                        message_type,
                        payload,
                    });
                },
                MessageType::String => {
                    // FIXED: Check if we have bytes for string length
                    if cursor.position() + 2 > len as u64 {
                        println!("Not enough bytes for string length");
                        break;
                    }
                    
                    let string_size = cursor.read_u16::<LittleEndian>().expect("Failed to read string size");
                    println!("String size: {}", string_size);

                    if cursor.position() + string_size as u64 > len as u64 {
                        println!("Not enough bytes for string content: need {}, have {}", 
                                string_size, len as u64 - cursor.position());
                        break;
                    }

                    let mut payload = vec![0; string_size as usize];
                    cursor.read_exact(&mut payload).expect("failed to read payload");
                    
                    // Remove null terminator if present
                    if let Some(&0) = payload.last() {
                        payload.pop();
                    }
                    
                    msg_list.push(Message {
                        message_type,
                        payload,
                    });
                },
                MessageType::Signed => {
                    // FIXED: Handle signed integers based on type_length
                    let size = match type_length {
                        1 => 1, // 8-bit
                        2 => 2, // 16-bit  
                        3 => 4, // 32-bit
                        4 => 8, // 64-bit
                        _ => {
                            println!("Invalid signed integer size: {}", type_length);
                            break;
                        }
                    };
                    
                    if cursor.position() + size as u64 > len as u64 {
                        println!("Not enough bytes for signed integer");
                        break;
                    }
                    
                    let mut payload = vec![0; size];
                    cursor.read_exact(&mut payload).expect("failed to read payload");
                    msg_list.push(Message {
                        message_type,
                        payload,
                    });
                },
                MessageType::Unsigned => {
                    // FIXED: Handle unsigned integers based on type_length
                    let size = match type_length {
                        1 => 1, // 8-bit
                        2 => 2, // 16-bit
                        3 => 4, // 32-bit  
                        4 => 8, // 64-bit
                        _ => {
                            println!("Invalid unsigned integer size: {}", type_length);
                            break;
                        }
                    };
                    
                    if cursor.position() + size as u64 > len as u64 {
                        println!("Not enough bytes for unsigned integer");
                        break;
                    }
                    
                    let mut payload = vec![0; size];
                    cursor.read_exact(&mut payload).expect("failed to read payload");
                    msg_list.push(Message {
                        message_type,
                        payload,
                    });
                },
                _ => {
                    println!("Unsupported message type: {:?}", message_type);
                    break;
                }
            }
        }

        println!("Parsed {} messages", msg_list.len());

        Self {
            msg_list,
        }
    }
}

pub trait DltParse {
    fn dlt_parse(&self) -> (Vec<DltFormat>, Vec<u8>);
}

impl DltParse for [u8] {
    fn dlt_parse(&self) -> (Vec<DltFormat>, Vec<u8>) {
        let mut remaining_data = Vec::new();
        let mut dlt_response: Vec<DltFormat> = Vec::new();
        let mut cursor: Cursor<Vec<u8>> = Cursor::new(self.to_vec());
        
        loop {
            let remaining_bytes = cursor.get_ref().len() - cursor.position() as usize;
            println!("Remaining bytes: {}", remaining_bytes);
            let message_start_pos = cursor.position();
            
            // Check if we have enough data for at least a standard header
            if remaining_bytes < DLT_STANDARD_HEADER_SIZE {
                cursor.read_to_end(&mut remaining_data).unwrap();
                break;
            }

            // Parse standard header
            let dlt_standard_header: DltStandardHeader = dlt_standard_header_parser(&mut cursor);

            // Check if we have the complete message
            println!("Standard Header Length: {}", dlt_standard_header.len);
            if dlt_standard_header.len < DLT_STANDARD_HEADER_SIZE as u16 {
                let mut remaining_data = Vec::new();
                cursor.set_position(cursor.position() - DLT_STANDARD_HEADER_SIZE as u64);
                cursor.read_to_end(&mut remaining_data).unwrap();
                break;
            }

            let message_remaining = dlt_standard_header.len as usize - DLT_STANDARD_HEADER_SIZE;
            let current_remaining = cursor.get_ref().len() - cursor.position() as usize;
            
            if current_remaining < message_remaining {
                let mut remaining_data = Vec::new();
                cursor.set_position(cursor.position() - DLT_STANDARD_HEADER_SIZE as u64);
                cursor.read_to_end(&mut remaining_data).unwrap();
                break;
            }

            // Parse headers
            let htyp = dlt_standard_header.get_htyp();
            let dlt_standard_header_extra: DltStandardHeaderExtra = 
                dlt_standard_header_extra_parser(&htyp, &mut cursor);
            let dlt_extended_header: DltExtendedHeader = 
                dlt_extended_header_parser(&htyp, &mut cursor);
            let mut payload_list: MessageList = MessageList::default();

            let mtin_type = dlt_extended_header.parse().2;
            match mtin_type {
                Mtin::Log(_) => {
                    println!("Log Message");
                    
                    // FIXED: Calculate correct payload position and length
                    let headers_size = dlt_standard_header_size() +
                                     dlt_standard_header_extra_size(&htyp) +
                                     dlt_extended_header_size(&htyp);
                    
                    let payload_start = message_start_pos as usize + headers_size;
                    let payload_length = dlt_standard_header.len as usize - headers_size;
                    
                    println!("Headers size: {}, Payload start: {}, Payload length: {}", 
                             headers_size, payload_start, payload_length);
                    
                    if payload_length > 0 && payload_start + payload_length <= cursor.get_ref().len() {
                        let payload_bytes = &cursor.get_ref()[payload_start..payload_start + payload_length];
                        println!("Payload bytes: {:?}", payload_bytes);
                        payload_list = MessageList::parse(payload_bytes, payload_length);
                    }
                    
                    // Set cursor to end of message
                    cursor.set_position(message_start_pos + dlt_standard_header.len as u64);
                },
                Mtin::Control(_) => {
                    println!("Control Message");
                    cursor.set_position(message_start_pos + dlt_standard_header.len as u64);
                },
                _ => {
                    println!("Other message type");
                    cursor.set_position(message_start_pos + dlt_standard_header.len as u64);
                },
            }
            
            // Add parsed message to response
            dlt_response.push(DltFormat {
                standard_header: dlt_standard_header,
                standard_header_extra: dlt_standard_header_extra,
                extended_header: dlt_extended_header,
                payload_list: payload_list,
            });

            // Check if we've processed all data
            if cursor.position() >= cursor.get_ref().len() as u64 {
                println!("All data processed");
                break;
            }
        }

        (dlt_response, remaining_data)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dlt_standard_header_extra_parser() {
        let data: [u8; _] = [
            0x35, 0x00, 0x00, 0x20, 0x45, 0x43, 0x55, 0x31, 0x82, 0x72, 0xD9, 0x99, 0x26, 0x01, 0x44, 0x41, 0x31, 0x00, 0x44, 0x43, 0x31, 0x00, 0x02, 0x0F, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x35, 0x00, 0x00, 0x20, 0x45, 0x43, 0x55, 0x31, 0x82, 0x70, 0x6C, 0xAB, 0x26, 0x01, 0x44, 0x41, 0x31, 0x00, 0x44, 0x43, 0x31, 0x00, 0x02, 0x0F, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x3D, 0x0E, 0x00, 0x4F, 0x45, 0x43, 0x55, 0x31, 0x00, 0x02, 0x57, 0x67, 0x82, 0x70, 0x6C, 0xAB, 0x41, 0x01, 0x44, 0x4C, 0x54, 0x44, 0x49, 0x4E, 0x54, 0x4D, 0x00, 0x02, 0x00, 0x00, 0x2F, 0x00, 0x43, 0x6C, 0x69, 0x65, 0x6E, 0x74, 0x20, 0x63, 0x6F, 0x6E, 0x6E, 0x65, 0x63, 0x74, 0x69, 0x6F, 0x6E, 0x20, 0x23, 0x37, 0x20, 0x63, 0x6C, 0x6F, 0x73, 0x65, 0x64, 0x2E, 0x20, 0x54, 0x6F, 0x74, 0x61, 0x6C, 0x20, 0x43, 0x6C, 0x69, 0x65, 0x6E, 0x74, 0x73, 0x20, 0x3A, 0x20, 0x30, 0x00, 0x3D, 0x0F, 0x00, 0x58, 0x45, 0x43, 0x55, 0x31, 0x00, 0x02, 0x57, 0x67, 0x82, 0x72, 0xD9, 0x9B, 0x41, 0x01, 0x44, 0x4C, 0x54, 0x44, 0x49, 0x4E, 0x54, 0x4D, 0x00, 0x02, 0x00, 0x00, 0x38, 0x00, 0x4E, 0x65, 0x77, 0x20, 0x63, 0x6C, 0x69, 0x65, 0x6E, 0x74, 0x20, 0x63, 0x6F, 0x6E, 0x6E, 0x65, 0x63, 0x74, 0x69, 0x6F, 0x6E, 0x20, 0x23, 0x37, 0x20, 0x65, 0x73, 0x74, 0x61, 0x62, 0x6C, 0x69, 0x73, 0x68, 0x65, 0x64, 0x2C, 0x20, 0x54, 0x6F, 0x74, 0x61, 0x6C, 0x20, 0x43, 0x6C, 0x69, 0x65, 0x6E, 0x74, 0x73, 0x20, 0x3A, 0x20, 0x31, 0x00,
            0x35, 0x00, 0x00, 0x20, 0x45, 0x43, 0x55, 0x31, 0x84, 0xE0, 0xE6, 0x1A, 0x26, 0x01, 0x44, 0x41, 0x31, 0x00, 0x44, 0x43, 0x31, 0x00, 0x02, 0x0F, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x35, 0x00, 0x00, 0x20, 0x45, 0x43, 0x55, 0x31, 0x84, 0xD8, 0x90, 0x13, 0x26, 0x01, 0x44, 0x41, 0x31, 0x00, 0x44, 0x43, 0x31, 0x00, 0x02, 0x0F, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x3D, 0x36, 0x00, 0x4F, 0x45, 0x43, 0x55, 0x31, 0x00, 0x02, 0x57, 0x67, 0x84, 0xD8, 0x90, 0x13, 0x41, 0x01, 0x44, 0x4C, 0x54, 0x44, 0x49, 0x4E, 0x54, 0x4D, 0x00, 0x02, 0x00, 0x00, 0x2F, 0x00, 0x43, 0x6C, 0x69, 0x65, 0x6E, 0x74, 0x20, 0x63, 0x6F, 0x6E, 0x6E, 0x65, 0x63, 0x74, 0x69, 0x6F, 0x6E, 0x20, 0x23, 0x37, 0x20, 0x63, 0x6C, 0x6F, 0x73, 0x65, 0x64, 0x2E, 0x20, 0x54, 0x6F, 0x74, 0x61, 0x6C, 0x20, 0x43, 0x6C, 0x69, 0x65, 0x6E, 0x74, 0x73, 0x20, 0x3A, 0x20, 0x30, 0x00, 0x3D, 0x37, 0x00, 0x58, 0x45, 0x43, 0x55, 0x31, 0x00, 0x02, 0x57, 0x67, 0x84, 0xE0, 0xE6, 0x1A, 0x41, 0x01, 0x44, 0x4C, 0x54, 0x44, 0x49, 0x4E, 0x54, 0x4D, 0x00, 0x02, 0x00, 0x00, 0x38, 0x00, 0x4E, 0x65, 0x77, 0x20, 0x63, 0x6C, 0x69, 0x65, 0x6E, 0x74, 0x20, 0x63, 0x6F, 0x6E, 0x6E, 0x65, 0x63, 0x74, 0x69, 0x6F, 0x6E, 0x20, 0x23, 0x37, 0x20, 0x65, 0x73, 0x74, 0x61, 0x62, 0x6C, 0x69, 0x73, 0x68, 0x65, 0x64, 0x2C, 0x20, 0x54, 0x6F, 0x74, 0x61, 0x6C, 0x20, 0x43, 0x6C, 0x69, 0x65, 0x6E, 0x74, 0x73, 0x20, 0x3A, 0x20, 0x31, 0x00
        ];

        let (dlt_analyzed_data, remaining_data) = data.dlt_parse();

        println!("{:?}", dlt_analyzed_data);

        let expected_header = DltStandardHeader {
            htyp: 61,
            mcnt: 0,
            len: 32, // Note the byte order
        };

        let expected_header_extra = DltStandardHeaderExtra {
            ecu: [0x44, 0x4C, 0x54, 0x31], // "DLT1"
            seid: 1,
            tmsp: 0x12345678,
        };

        let expected_exnteded_header = DltExtendedHeader {
            msin: 65, // "DLT1"
            noar: 32,
            apid: *b"DLTD",
            ctid: *b"INTM",
        };

        assert_eq!(dlt_analyzed_data[0].standard_header, expected_header);
        assert_eq!(dlt_analyzed_data[0].extended_header, expected_exnteded_header);
    }

    #[test]
    fn test_dlt_paser_log() {
        let data: [u8; _] = [
            0x3D, 0x12, 0x00, 0x78, 0x45, 0x43, 0x55, 0x31, 0x00, 0x02, 0x57, 0x67, 0x82, 0xA2, 0xD2, 0xDF, 0x41, 0x01, 0x44, 0x4C, 0x54, 0x44, 0x49, 0x4E, 0x54, 0x4D, 0x00, 0x02, 0x00, 0x00, 0x58, 0x00, 0x41, 0x70, 0x70, 0x6C, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x49, 0x44, 0x20, 0x27, 0x4C, 0x4F, 0x47, 0x27, 0x20, 0x72, 0x65, 0x67, 0x69, 0x73, 0x74, 0x65, 0x72, 0x65, 0x64, 0x20, 0x66, 0x6F, 0x72, 0x20, 0x50, 0x49, 0x44, 0x20, 0x31, 0x36, 0x31, 0x35, 0x32, 0x33, 0x2C, 0x20, 0x44, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6F, 0x6E, 0x3D, 0x54, 0x65, 0x73, 0x74, 0x20, 0x41, 0x70, 0x70, 0x6C, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x20, 0x66, 0x6F, 0x72, 0x20, 0x4C, 0x6F, 0x67, 0x67, 0x69, 0x6E, 0x67, 0x00, 0x35, 0x00, 0x00, 0x65, 0x45, 0x43, 0x55, 0x31, 0x82, 0xA2, 0xD2, 0xE0, 0x26, 0x01, 0x44, 0x41, 0x31, 0x00, 0x44, 0x43, 0x31, 0x00, 0x03, 0x00, 0x00, 0x00, 0x07, 0x01, 0x00, 0x4C, 0x4F, 0x47, 0x00, 0x01, 0x00, 0x54, 0x45, 0x53, 0x54, 0xFF, 0xFF, 0x18, 0x00, 0x54, 0x65, 0x73, 0x74, 0x20, 0x43, 0x6F, 0x6E, 0x74, 0x65, 0x78, 0x74, 0x20, 0x66, 0x6F, 0x72, 0x20, 0x4C, 0x6F, 0x67, 0x67, 0x69, 0x6E, 0x67, 0x1C, 0x00, 0x54, 0x65, 0x73, 0x74, 0x20, 0x41, 0x70, 0x70, 0x6C, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x20, 0x66, 0x6F, 0x72, 0x20, 0x4C, 0x6F, 0x67, 0x67, 0x69, 0x6E, 0x67, 0x72, 0x65, 0x6D, 0x6F, 0x35, 0x00, 0x00, 0x68, 0x45, 0x43, 0x55, 0x31, 0x82, 0xA2, 0xD2, 0xE1, 0x26, 0x01, 0x44, 0x41, 0x31, 0x00, 0x44, 0x43, 0x31, 0x00, 0x03, 0x00, 0x00, 0x00, 0x07, 0x01, 0x00, 0x4C, 0x4F, 0x47, 0x00, 0x01, 0x00, 0x54, 0x53, 0x31, 0x00, 0xFF, 0xFF, 0x1B, 0x00, 0x54, 0x65, 0x73, 0x74, 0x20, 0x43, 0x6F, 0x6E, 0x74, 0x65, 0x78, 0x74, 0x31, 0x20, 0x66, 0x6F, 0x72, 0x20, 0x69, 0x6E, 0x6A, 0x65, 0x63, 0x74, 0x69, 0x6F, 0x6E, 0x1C, 0x00, 0x54, 0x65, 0x73, 0x74, 0x20, 0x41, 0x70, 0x70, 0x6C, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x20, 0x66, 0x6F, 0x72, 0x20, 0x4C, 0x6F, 0x67, 0x67, 0x69, 0x6E, 0x67, 0x72, 0x65, 0x6D, 0x6F, 0x35, 0x00, 0x00, 0x68, 0x45, 0x43, 0x55, 0x31, 0x82, 0xA2, 0xD2, 0xE2, 0x26, 0x01, 0x44, 0x41, 0x31, 0x00, 0x44, 0x43, 0x31, 0x00, 0x03, 0x00, 0x00, 0x00, 0x07, 0x01, 0x00, 0x4C, 0x4F, 0x47, 0x00, 0x01, 0x00, 0x54, 0x53, 0x32, 0x00, 0xFF, 0xFF, 0x1B, 0x00, 0x54, 0x65, 0x73, 0x74, 0x20, 0x43, 0x6F, 0x6E, 0x74, 0x65, 0x78, 0x74, 0x32, 0x20, 0x66, 0x6F, 0x72, 0x20, 0x69, 0x6E, 0x6A, 0x65, 0x63, 0x74, 0x69, 0x6F, 0x6E, 0x1C, 0x00, 0x54, 0x65, 0x73, 0x74, 0x20, 0x41, 0x70, 0x70, 0x6C, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x20, 0x66, 0x6F, 0x72, 0x20, 0x4C, 0x6F, 0x67, 0x67, 0x69, 0x6E, 0x67, 0x72, 0x65, 0x6D, 0x6F, 0x3D, 0x00, 0x00, 0x34, 0x45, 0x43, 0x55, 0x31, 0x00, 0x02, 0x76, 0xF3, 0x82, 0xA2, 0xD2, 0xDC, 0x31, 0x02, 0x4C, 0x4F, 0x47, 0x00, 0x54, 0x45, 0x53, 0x54, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x0C, 0x00, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x00, 0x3D, 0x01, 0x00, 0x34, 0x45, 0x43, 0x55, 0x31, 0x00, 0x02, 0x76, 0xF3, 0x82, 0xA2, 0xE6, 0x71, 0x31, 0x02, 0x4C, 0x4F, 0x47, 0x00, 0x54, 0x45, 0x53, 0x54, 0x23, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x0C, 0x00, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x00, 0x3D, 0x02, 0x00, 0x34, 0x45, 0x43, 0x55, 0x31, 0x00, 0x02, 0x76, 0xF3, 0x82, 0xA2, 0xF9, 0xFD, 0x31, 0x02, 0x4C, 0x4F, 0x47, 0x00, 0x54, 0x45, 0x53, 0x54, 0x23, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x0C, 0x00, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x00
        ];

        let (dlt_analyzed_data, remaining_data) = data.dlt_parse();

        //println!("{:?}", dlt_analyzed_data);

        let expected_header = DltStandardHeader {
            htyp: 0x3d,
            mcnt: 18,
            len: 120, // Note the byte order
        };

        let expected_header_extra = DltStandardHeaderExtra {
            ecu: *b"ECU1", // "DLT1"
            seid: 153447,
            tmsp: 2191708895,
        };

        let expected_exnteded_header = DltExtendedHeader {
            msin: 65, // "DLT1"
            noar: 1,
            apid: *b"DLTD",
            ctid: *b"INTM",
        };

        let payload = *b"ApplicationID 'LOG' registered for PID 161523, Description=Test Application for Logging\0";
        println!("{:?}", dlt_analyzed_data[0].payload_list.get_entire_string());

        assert_eq!(dlt_analyzed_data[0].standard_header, expected_header);
        assert_eq!(dlt_analyzed_data[0].standard_header_extra, expected_header_extra);
        assert_eq!(dlt_analyzed_data[0].extended_header, expected_exnteded_header);
        assert_eq!(dlt_analyzed_data[0].payload_list.get_entire_string().as_bytes(), payload);
    }

    #[test]
    fn test_dlt_service_msg() {
        let data: [u8; _] = [
            0x35, 0x00, 0x00, 0x27, 0x45, 0x43, 0x55, 0x31, 0x84, 0xEF, 0x38, 0x78, 0x26, 0x01, 0x44, 0x41, 0x31, 0x00, 0x44, 0x43, 0x31, 0x00, 0x01, 0x0F, 0x00, 0x00, 0x00, 0x4C, 0x4F, 0x47, 0x00, 0x54, 0x45, 0x53, 0x54, 0x72, 0x65, 0x6D, 0x6F, 0x3D, 0x39, 0x00, 0x38, 0x45, 0x43, 0x55, 0x31, 0x00, 0x02, 0x57, 0x67, 0x84, 0xEF, 0x38, 0x79, 0x41, 0x01, 0x44, 0x4C, 0x54, 0x44, 0x49, 0x4E, 0x54, 0x4D, 0x00, 0x02, 0x00, 0x00, 0x18, 0x00, 0x55, 0x6E, 0x72, 0x65, 0x67, 0x69, 0x73, 0x74, 0x65, 0x72, 0x65, 0x64, 0x20, 0x41, 0x70, 0x49, 0x44, 0x20, 0x27, 0x4C, 0x4F, 0x47, 0x27, 0x00
        ];

        let (dlt_analyzed_data, remaining_data) = data.dlt_parse();
        println!("{:?}", dlt_analyzed_data);
        

        
        assert_eq!(dlt_analyzed_data.len(), 2);
        assert_eq!(remaining_data.len(), 0);

    }
}
