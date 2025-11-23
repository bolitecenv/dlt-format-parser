use std::io::Cursor;
use std::io::Read;
use std::fmt;
use byteorder::{LittleEndian, ReadBytesExt};

pub const DLT_ID_SIZE: usize = 4;

pub const DLT_STORAGE_HEADER_SIZE: usize = 16;
pub const DLT_STANDARD_HEADER_SIZE: usize = 4;
pub const DLT_EXTENDED_HEADER_SIZE: usize = 10; // Fixed: was "onst"
pub const DLT_STANDARD_HEADER_EXTRA_SIZE: usize = 12;
pub const DLT_STANDARD_HEADER_EXTRA_NOSESSIONID_SIZE: usize = 8;
pub const DLT_PAYLOAD_HEADER_SIZE: usize = 6;

pub const UEH_MASK: u8  = 0x01; // Bit 0: Use Extended Header
pub const MSBF_MASK: u8 = 0x02; // Bit 1: Most Significant Byte First
pub const WEID_MASK: u8 = 0x04; // Bit 2: With ECU ID
pub const WSID_MASK: u8 = 0x08; // Bit 3: With Session ID
pub const WTMS_MASK: u8 = 0x10; // Bit 4: With Timestamp
pub const VERS_MASK: u8 = 0xE0; // Bit 5-7: Version Number (11100000)


#[derive(Debug, PartialEq)]
pub struct DltHTYP {
    pub UEH: bool,
    pub MSBF: bool, 
    pub WEID: bool,
    pub WSID: bool,
    pub WTMS: bool,
    pub VERS: u8,
}


#[derive(Debug, PartialEq, Default)]
pub struct DltStandardHeader {
    pub htyp:   u8,
    pub mcnt:   u8,
    pub len:    u16,
}

#[derive(Debug, PartialEq, Default)]
pub struct DltStandardHeaderExtra {
    pub ecu: [u8; DLT_ID_SIZE],
    pub seid: u32,
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
    pub service_cmd: u32
}

#[derive(Debug)]
pub enum MstpType {
    DltTypeLog,
    DltTypeAppTrace,
    DltTypeNwTrace,
    DltTypeControl,
    Reserved(u8),
    Invalid(u8),
}

impl MstpType {
    pub fn parse(value: u8) -> MstpType {
        match value {
            0x0 => MstpType::DltTypeLog,
            0x1 => MstpType::DltTypeAppTrace,
            0x2 => MstpType::DltTypeNwTrace,
            0x3 => MstpType::DltTypeControl,
            0x4..=0x7 => MstpType::Reserved(value), // Fixed: was 0x4..7
            _ => MstpType::Invalid(value),
        }
    }
}

impl fmt::Display for MstpType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MstpType::DltTypeLog => write!(f, "DltTypeLog"),
            MstpType::DltTypeAppTrace => write!(f, "DltTypeAppTrace"),
            MstpType::DltTypeNwTrace => write!(f, "DltTypeNwTrace"),
            MstpType::DltTypeControl => write!(f, "DltTypeControl"),
            MstpType::Reserved(val) => write!(f, "Reserved({})", val),
            MstpType::Invalid(val) => write!(f, "Invalid({})", val),
        }
    }
}

#[derive(Debug)]
pub enum Mtin {
    Log(MtinTypeDltLog),
    AppTrace(MtinTypeDltAppTrace),
    NwTrace(MtinTypeDltNwTrace),
    Control(MtinTypeDltControl),
    Invalid,
}


#[derive(Debug)]
pub enum MtinTypeDltLog{
    DltLogFatal,
    DltLogError,
    DltLogWarn,
    DltLogInfo,
    DltLogDebug,
    DltLogVerbose,
    Reserved(u8),
    Invalid(u8),
}

#[derive(Debug)]
pub enum MtinTypeDltAppTrace {
    DltTraceVariable,
    Reserved(u8),
    Invalid(u8),
}

#[derive(Debug)]
pub enum MtinTypeDltNwTrace {
    DltTraceVariable,
    Reserved(u8),
    Invalid(u8),
}

#[derive(Debug)]
pub enum MtinTypeDltControl {
    DltControlRequest,
    DltControlResponse,
    Reserved(u8),
    Invalid(u8),
}

impl MtinTypeDltLog {
    pub fn parse(value: u8) -> MtinTypeDltLog {
        match value {
            0x0 => MtinTypeDltLog::DltLogFatal,
            0x1 => MtinTypeDltLog::DltLogError,
            0x2 => MtinTypeDltLog::DltLogWarn,
            0x3 => MtinTypeDltLog::DltLogInfo,
            0x4 => MtinTypeDltLog::DltLogDebug,
            0x5 => MtinTypeDltLog::DltLogVerbose,
            0x6..=0x7 => MtinTypeDltLog::Reserved(value), // Fixed: was 0x6..0x7
            _ => MtinTypeDltLog::Invalid(value),
        }
    }
}

impl MtinTypeDltAppTrace {
    pub fn parse(value: u8) -> MtinTypeDltAppTrace {
        MtinTypeDltAppTrace::Invalid(value)
    }
}

impl MtinTypeDltNwTrace {
    pub fn parse(value: u8) -> MtinTypeDltNwTrace {
        MtinTypeDltNwTrace::Invalid(value)
    }
}

impl MtinTypeDltControl {
    pub fn parse(value: u8) -> MtinTypeDltControl {
        match value {
            0x1 => MtinTypeDltControl::DltControlRequest,
            0x2 => MtinTypeDltControl::DltControlResponse,
            0x3..=0x7 => MtinTypeDltControl::Reserved(value), // Fixed: was 0x3..0x7
            _ => MtinTypeDltControl::Invalid(value),
        }
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

    pub fn serialize(&self) -> Vec<u8> {
        let mut packet = Vec::new();

        packet.extend(&self.htyp.to_be_bytes());
        packet.extend(&self.mcnt.to_be_bytes());
        packet.extend(&self.len.to_be_bytes());

        packet
    }

    pub fn get_version(&self) -> u8 {
        let VERS: u8 = (self.htyp & VERS_MASK) >> 5;
        VERS
    }

    pub fn is_tmsp_enabled(&self) -> bool {
        (self.htyp & WTMS_MASK) != 0
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
    pub fn serialize(&self, htype: u8) -> Vec<u8> {
        let mut packet = Vec::new();

        if (htype & WEID_MASK) != 0 {
            packet.extend_from_slice(&self.ecu);
        }
        if (htype & WSID_MASK) != 0 {
            packet.extend(&self.seid.to_be_bytes());
        }
        if (htype & WTMS_MASK) != 0 {
            packet.extend(&self.tmsp.to_be_bytes());
        }

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
    pub fn serialize(&self) -> Vec<u8> {
        let mut packet = Vec::new();

        packet.extend(&self.msin.to_be_bytes());
        packet.extend(&self.noar.to_be_bytes());
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
            MstpType::DltTypeLog => Mtin::Log(MtinTypeDltLog::parse(mtin_val)),
            MstpType::DltTypeAppTrace => Mtin::AppTrace(MtinTypeDltAppTrace::parse(mtin_val)),
            MstpType::DltTypeNwTrace => Mtin::NwTrace(MtinTypeDltNwTrace::parse(mtin_val)),
            MstpType::DltTypeControl => Mtin::Control(MtinTypeDltControl::parse(mtin_val)),
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
                    // println!("TODO: {:?}", message);
                }
            }
        }

        message_string
    }

    pub fn parse(data: &[u8], len: usize) -> Self {
        if len < 4 {
            println!("Data is too short: {} bytes", len);
            return Self::default();
        }

        let mut msg_list: Vec<Message> = Vec::new();
        let mut cursor = Cursor::new(data.to_vec());

        while cursor.position() < len as u64 {            
            // FIXED: Read the type info correctly
            if cursor.position() + 4 > len as u64 {
                println!("Not enough bytes for type header");
                break;
            }
            
            let type_byte = cursor.read_u32::<LittleEndian>().expect("Failed to read type byte");

            // FIXED: Extract type length from the first byte
            let type_length = (type_byte & 0x0F) as u8;

            let message_type = match Self::parse_type(type_byte) {
                Some(mt) => mt,
                None => {
                    println!("Invalid message type: 0x{:08X}", type_byte);
                    break;
                }
            };

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

        Self {
            msg_list,
        }
    }
}