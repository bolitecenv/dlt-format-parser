use std::collections::HashMap;
use crate::types::DLT_ID_SIZE;

pub const SWC_INJECTION_MIN: u32 = 0x00000fff;
pub const SWC_INJECTION_MAX: u32 = 0xffffffff;

/// Represents all available service types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ServiceType {
    SetLogLevel = 0x01,
    SetTraceStatus = 0x02,
    GetLogInfo = 0x03,
    GetDefaultLogLevel = 0x04,
    StoreConfiguration = 0x05,
    RestoreToFactoryDefault = 0x06,
    SetMessageFiltering = 0x0A,
    SetDefaultLogLevel = 0x11,
    SetDefaultTraceStatus = 0x12,
    GetSoftwareVersion = 0x13,
    GetDefaultTraceStatus = 0x15,
    GetLogChannelNames = 0x17,
    GetTraceStatus = 0x1F,
    SetLogChannelAssignment = 0x20,
    SetLogChannelThreshold = 0x21,
    GetLogChannelThreshold = 0x22,
    BufferOverflowNotification = 0x23,
    SyncTimeStamp = 0x24,
    SWCInjection,
}

impl ServiceType {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0x00000001 => Some(ServiceType::SetLogLevel),
            0x00000002 => Some(ServiceType::SetTraceStatus),
            0x00000003 => Some(ServiceType::GetLogInfo),
            0x00000004 => Some(ServiceType::GetDefaultLogLevel),
            0x00000005 => Some(ServiceType::StoreConfiguration),
            0x00000006 => Some(ServiceType::RestoreToFactoryDefault),
            0x0000000A => Some(ServiceType::SetMessageFiltering),
            0x00000011 => Some(ServiceType::SetDefaultLogLevel),
            0x00000012 => Some(ServiceType::SetDefaultTraceStatus),
            0x00000013 => Some(ServiceType::GetSoftwareVersion),
            0x00000015 => Some(ServiceType::GetDefaultTraceStatus),
            0x00000017 => Some(ServiceType::GetLogChannelNames),
            0x0000001F => Some(ServiceType::GetTraceStatus),
            0x00000020 => Some(ServiceType::SetLogChannelAssignment),
            0x00000021 => Some(ServiceType::SetLogChannelThreshold),
            0x00000022 => Some(ServiceType::GetLogChannelThreshold),
            0x00000023 => Some(ServiceType::BufferOverflowNotification),
            0x00000024 => Some(ServiceType::SyncTimeStamp),
            v if (v >= SWC_INJECTION_MIN && v <= SWC_INJECTION_MAX) => Some(ServiceType::SWCInjection),
            _ => None,
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            ServiceType::SetLogLevel => "Set the Log Level",
            ServiceType::SetTraceStatus => "Enable/Disable Trace Messages",
            ServiceType::GetLogInfo => "Returns the LogLevel for applications",
            ServiceType::GetDefaultLogLevel => "Returns the LogLevel for wildcards",
            ServiceType::StoreConfiguration => "Stores the current configuration non volatile",
            ServiceType::RestoreToFactoryDefault => "Sets the configuration back to default",
            ServiceType::SetMessageFiltering => "Enable/Disable message filtering",
            ServiceType::SetDefaultLogLevel => "Sets the LogLevel for wildcards",
            ServiceType::SetDefaultTraceStatus => "Enable/Disable TraceMessages for wildcards",
            ServiceType::GetSoftwareVersion => "Get the ECU software version",
            ServiceType::GetDefaultTraceStatus => "Get the current TraceLevel for wildcards",
            ServiceType::GetLogChannelNames => "Returns the LogChannel's name",
            ServiceType::GetTraceStatus => "Returns the current TraceStatus",
            ServiceType::SetLogChannelAssignment => "Adds/ Removes the given LogChannel as output path",
            ServiceType::SetLogChannelThreshold => "Sets the filter threshold for the given LogChannel",
            ServiceType::GetLogChannelThreshold => "Returns the current LogLevel for a given LogChannel",
            ServiceType::BufferOverflowNotification => "Report that a buffer overflow occurred",
            ServiceType::SyncTimeStamp => "Reports synchronized absolute time",
            ServiceType::SWCInjection => "SWC injection id (within SWC injection range)",
        }
    }
}

/// Trait for parsing binary data
pub trait FromBytes: Sized {
    fn from_bytes(data: &[u8]) -> Result<Self, ParseError>;
}

/// Trait for serializing to binary data  
pub trait ToBytes {
    fn to_bytes(&self) -> Vec<u8>;
}

/// Parse error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    InsufficientData { expected: usize, actual: usize },
    InvalidStatus(u8),
    InvalidData(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::InsufficientData { expected, actual } => {
                write!(f, "Insufficient data: expected {} bytes, got {}", expected, actual)
            }
            ParseError::InvalidStatus(status) => {
                write!(f, "Invalid status value: {}", status)
            }
            ParseError::InvalidData(msg) => {
                write!(f, "Invalid data: {}", msg)
            }
        }
    }
}


impl std::error::Error for ParseError {}

// Request structures for each service
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceSetLogLevelRequest {
    pub apid: [u8; DLT_ID_SIZE],
    pub ctid: [u8; DLT_ID_SIZE],
    pub new_log_level: u8,
    pub reserved: [u8; DLT_ID_SIZE],
}

impl FromBytes for ServiceSetLogLevelRequest {
    fn from_bytes(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < DLT_ID_SIZE + DLT_ID_SIZE + 1 + DLT_ID_SIZE {
            return Err(ParseError::InsufficientData { 
                expected: DLT_ID_SIZE + DLT_ID_SIZE + 1 + DLT_ID_SIZE, 
                actual: data.len() 
            });
        }
        
        let mut apid = [0u8; DLT_ID_SIZE];
        let mut ctid = [0u8; DLT_ID_SIZE];
        let mut reserved = [0u8; DLT_ID_SIZE];
        
        apid.copy_from_slice(&data[0..DLT_ID_SIZE]);
        ctid.copy_from_slice(&data[DLT_ID_SIZE..DLT_ID_SIZE*2]);
        let new_log_level = data[DLT_ID_SIZE*2];
        reserved.copy_from_slice(&data[DLT_ID_SIZE*2+1..DLT_ID_SIZE*2+1+DLT_ID_SIZE]);
        
        Ok(Self { apid, ctid, new_log_level, reserved })
    }
}

impl ToBytes for ServiceSetLogLevelRequest {
    fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.apid);
        result.extend_from_slice(&self.ctid);
        result.push(self.new_log_level);
        result.extend_from_slice(&self.reserved);
        result
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceSetTraceStatusRequest {
    pub apid: [u8; DLT_ID_SIZE],
    pub ctid: [u8; DLT_ID_SIZE],
    pub new_trace_status: u8,
    pub reserved: [u8; DLT_ID_SIZE],
}

impl FromBytes for ServiceSetTraceStatusRequest {
    fn from_bytes(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < DLT_ID_SIZE + DLT_ID_SIZE + 1 + DLT_ID_SIZE {
            return Err(ParseError::InsufficientData { 
                expected: DLT_ID_SIZE + DLT_ID_SIZE + 1 + DLT_ID_SIZE, 
                actual: data.len() 
            });
        }
        
        let mut apid = [0u8; DLT_ID_SIZE];
        let mut ctid = [0u8; DLT_ID_SIZE];
        let mut reserved = [0u8; DLT_ID_SIZE];
        
        apid.copy_from_slice(&data[0..DLT_ID_SIZE]);
        ctid.copy_from_slice(&data[DLT_ID_SIZE..DLT_ID_SIZE*2]);
        let new_trace_status = data[DLT_ID_SIZE*2];
        reserved.copy_from_slice(&data[DLT_ID_SIZE*2+1..DLT_ID_SIZE*2+1+DLT_ID_SIZE]);
        
        Ok(Self { apid, ctid, new_trace_status, reserved })
    }
}

impl ToBytes for ServiceSetTraceStatusRequest {
    fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&self.apid);
        result.extend_from_slice(&self.ctid);
        result.push(self.new_trace_status);
        result.extend_from_slice(&self.reserved);
        result
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceGetLogInfoRequest {
    pub options: u8,
    pub apid: [u8; DLT_ID_SIZE],
    pub ctid: [u8; DLT_ID_SIZE],
    pub reserved: [u8; DLT_ID_SIZE],
}

impl FromBytes for ServiceGetLogInfoRequest {
    fn from_bytes(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < 1 + DLT_ID_SIZE + DLT_ID_SIZE + DLT_ID_SIZE {
            return Err(ParseError::InsufficientData { 
                expected: 1 + DLT_ID_SIZE + DLT_ID_SIZE + DLT_ID_SIZE, 
                actual: data.len() 
            });
        }
        
        let options = data[0];
        let mut apid = [0u8; DLT_ID_SIZE];
        let mut ctid = [0u8; DLT_ID_SIZE];
        let mut reserved = [0u8; DLT_ID_SIZE];
        
        apid.copy_from_slice(&data[1..1+DLT_ID_SIZE]);
        ctid.copy_from_slice(&data[1+DLT_ID_SIZE..1+DLT_ID_SIZE*2]);
        reserved.copy_from_slice(&data[1+DLT_ID_SIZE*2..1+DLT_ID_SIZE*3]);
        
        Ok(Self { options, apid, ctid, reserved })
    }
}

impl ToBytes for ServiceGetLogInfoRequest {
    fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.push(self.options);
        result.extend_from_slice(&self.apid);
        result.extend_from_slice(&self.ctid);
        result.extend_from_slice(&self.reserved);
        result
    }
}

#[derive(Debug, Clone)]
pub enum LogInfoStatus {
    NotSupported = 1,
    DltError = 2,
    Reserved3 = 3,
    Reserved4 = 4,
    UnregisteredInfo = 5,
    RegisteredWithLogLevel = 6,
    RegisteredWithDescriptions = 7,
    NoMatchingContextIds = 8,
    ResponseDataOverflow = 9,
}

impl TryFrom<u8> for LogInfoStatus {
    type Error = ParseError;
    
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(LogInfoStatus::NotSupported),
            2 => Ok(LogInfoStatus::DltError),
            3 => Ok(LogInfoStatus::Reserved3),
            4 => Ok(LogInfoStatus::Reserved4),
            5 => Ok(LogInfoStatus::UnregisteredInfo),
            6 => Ok(LogInfoStatus::RegisteredWithLogLevel),
            7 => Ok(LogInfoStatus::RegisteredWithDescriptions),
            8 => Ok(LogInfoStatus::NoMatchingContextIds),
            9 => Ok(LogInfoStatus::ResponseDataOverflow),
            _ => Err(ParseError::InvalidStatus(value)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ContextIdInfo {
    pub context_id: [u8; DLT_ID_SIZE],
    pub log_level: u8,  // enum 0x00 .. 0x06
    pub trace_status: u8,
    pub context_description: Option<Vec<u8>>,  // Only for status 7
}

#[derive(Debug, Clone)]
pub struct AppIdInfo {
    pub app_id: [u8; DLT_ID_SIZE],
    pub context_id_count: u16,
    pub context_id_list: Vec<ContextIdInfo>,
    pub app_description: Option<Vec<u8>>,  // Only for status 7
}

#[derive(Debug, Clone)]
pub enum LogInfoData {
    None,  // For status 1, 2, 8, 9
    ApplicationIds(Vec<AppIdInfo>),  // For status 5, 6, 7
}

#[derive(Debug, Clone)]
pub struct ServiceGetLogInfoResponse {
    pub status: u8,
    pub log_info_data: LogInfoData,
    pub reserved: [u8; 4],
}

impl FromBytes for ServiceGetLogInfoResponse {
    fn from_bytes(data: &[u8]) -> Result<Self, ParseError> {
        // Minimum size: status (1) + reserved (4) = 5 bytes
        if data.len() < 5 {
            return Err(ParseError::InsufficientData {
                expected: 5,
                actual: data.len(),
            });
        }
        
        let status = data[0];
        let status_enum = LogInfoStatus::try_from(status)?;
        println!("status:: {}", status);
        // Reserved bytes are at the end
        let data_end = data.len() - 4;
        let mut reserved = [0u8; 4];
        reserved.copy_from_slice(&data[data_end..]);
        
        let log_info_data = match status_enum {
            LogInfoStatus::NotSupported | 
            LogInfoStatus::DltError | 
            LogInfoStatus::NoMatchingContextIds |
            LogInfoStatus::ResponseDataOverflow => {
                // No application ID data for these statuses
                LogInfoData::None
            }
            LogInfoStatus::UnregisteredInfo |
            LogInfoStatus::RegisteredWithLogLevel |
            LogInfoStatus::RegisteredWithDescriptions => {
                // Parse application IDs data
                if data.len() < 7 {  // status(1) + app_count(2) + reserved(4)
                    return Err(ParseError::InsufficientData {
                        expected: 7,
                        actual: data.len(),
                    });
                }
                
                let mut offset = 1;  // Skip status byte
                let app_id_count = u16::from_be_bytes([data[offset], data[offset + 1]]);
                offset += 2;
                
                let mut app_ids = Vec::new();
                
                for _ in 0..app_id_count {
                    if offset + DLT_ID_SIZE > data_end {
                        return Err(ParseError::InsufficientData {
                            expected: offset + DLT_ID_SIZE,
                            actual: data_end,
                        });
                    }
                    
                    let mut app_id = [0u8; DLT_ID_SIZE];
                    app_id.copy_from_slice(&data[offset..offset + DLT_ID_SIZE]);
                    offset += DLT_ID_SIZE;
                    
                    if offset + 2 > data_end {
                        return Err(ParseError::InsufficientData {
                            expected: offset + 2,
                            actual: data_end,
                        });
                    }
                    
                    let context_id_count = u16::from_be_bytes([data[offset], data[offset + 1]]);
                    offset += 2;
                    
                    let mut context_id_list = Vec::new();
                    
                    for _ in 0..context_id_count {
                        if offset + DLT_ID_SIZE + 2 > data_end {
                            return Err(ParseError::InsufficientData {
                                expected: offset + DLT_ID_SIZE + 2,
                                actual: data_end,
                            });
                        }
                        
                        let mut context_id = [0u8; DLT_ID_SIZE];
                        context_id.copy_from_slice(&data[offset..offset + DLT_ID_SIZE]);
                        offset += DLT_ID_SIZE;
                        
                        let log_level = data[offset];
                        offset += 1;
                        
                        let trace_status = data[offset];
                        offset += 1;
                        
                        let context_description = if status == 7 {
                            // Parse context description for verbose mode
                            if offset + 2 > data_end {
                                return Err(ParseError::InsufficientData {
                                    expected: offset + 2,
                                    actual: data_end,
                                });
                            }
                            
                            let len_context_desc = u16::from_be_bytes([data[offset], data[offset + 1]]);
                            offset += 2;
                            
                            if offset + len_context_desc as usize > data_end {
                                return Err(ParseError::InsufficientData {
                                    expected: offset + len_context_desc as usize,
                                    actual: data_end,
                                });
                            }
                            
                            let desc = data[offset..offset + len_context_desc as usize].to_vec();
                            offset += len_context_desc as usize;
                            Some(desc)
                        } else {
                            None
                        };
                        
                        context_id_list.push(ContextIdInfo {
                            context_id,
                            log_level,
                            trace_status,
                            context_description,
                        });
                    }
                    
                    let app_description = if status == 7 {
                        // Parse app description for verbose mode
                        if offset + 2 > data_end {
                            return Err(ParseError::InsufficientData {
                                expected: offset + 2,
                                actual: data_end,
                            });
                        }
                        
                        let app_desc_len = u16::from_be_bytes([data[offset], data[offset + 1]]);
                        offset += 2;
                        
                        if offset + app_desc_len as usize > data_end {
                            return Err(ParseError::InsufficientData {
                                expected: offset + app_desc_len as usize,
                                actual: data_end,
                            });
                        }
                        
                        let desc = data[offset..offset + app_desc_len as usize].to_vec();
                        offset += app_desc_len as usize;
                        Some(desc)
                    } else {
                        None
                    };
                    
                    app_ids.push(AppIdInfo {
                        app_id,
                        context_id_count,
                        context_id_list,
                        app_description,
                    });
                }
                
                LogInfoData::ApplicationIds(app_ids)
            }
            LogInfoStatus::Reserved3 | LogInfoStatus::Reserved4 => {
                // Handle reserved statuses - treat as no data
                LogInfoData::None
            }
        };
        
        Ok(Self {
            status,
            log_info_data,
            reserved,
        })
    }
}

impl ToBytes for ServiceGetLogInfoResponse {
    fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        
        // Add status byte
        result.push(self.status);
        
        // Add log info data based on status
        match &self.log_info_data {
            LogInfoData::None => {
                // No additional data
            }
            LogInfoData::ApplicationIds(app_ids) => {
                // Add app ID count
                result.extend_from_slice(&(app_ids.len() as u16).to_be_bytes());
                
                for app_info in app_ids {
                    // Add app ID
                    result.extend_from_slice(&app_info.app_id);
                    
                    // Add context ID count
                    result.extend_from_slice(&app_info.context_id_count.to_be_bytes());
                    
                    // Add context IDs
                    for ctx_info in &app_info.context_id_list {
                        result.extend_from_slice(&ctx_info.context_id);
                        result.push(ctx_info.log_level);
                        result.push(ctx_info.trace_status);
                        
                        // Add context description if status is 7 (verbose mode)
                        if self.status == 7 {
                            if let Some(ref desc) = ctx_info.context_description {
                                result.extend_from_slice(&(desc.len() as u16).to_be_bytes());
                                result.extend_from_slice(desc);
                            } else {
                                result.extend_from_slice(&0u16.to_be_bytes());
                            }
                        }
                    }
                    
                    // Add app description if status is 7 (verbose mode)
                    if self.status == 7 {
                        if let Some(ref desc) = app_info.app_description {
                            result.extend_from_slice(&(desc.len() as u16).to_be_bytes());
                            result.extend_from_slice(desc);
                        } else {
                            result.extend_from_slice(&0u16.to_be_bytes());
                        }
                    }
                }
            }
        }
        
        // Add reserved bytes at the end
        result.extend_from_slice(&self.reserved);
        
        result
    }
}

// Add more request structures for other services as needed
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceSetDefaultLogLevelRequest {
    pub new_log_level: u8,
    pub reserved: [u8; 3],
}

impl FromBytes for ServiceSetDefaultLogLevelRequest {
    fn from_bytes(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < 4 {
            return Err(ParseError::InsufficientData { expected: 4, actual: data.len() });
        }
        
        let new_log_level = data[0];
        let mut reserved = [0u8; 3];
        reserved.copy_from_slice(&data[1..4]);
        
        Ok(Self { new_log_level, reserved })
    }
}

impl ToBytes for ServiceSetDefaultLogLevelRequest {
    fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.push(self.new_log_level);
        result.extend_from_slice(&self.reserved);
        result
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceSetMessageFilteringRequest {
    pub new_status: u8,
    pub reserved: [u8; 3],
}

impl FromBytes for ServiceSetMessageFilteringRequest {
    fn from_bytes(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < 4 {
            return Err(ParseError::InsufficientData { expected: 4, actual: data.len() });
        }
        
        let new_status = data[0];
        let mut reserved = [0u8; 3];
        reserved.copy_from_slice(&data[1..4]);
        
        Ok(Self { new_status, reserved })
    }
}

impl ToBytes for ServiceSetMessageFilteringRequest {
    fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.push(self.new_status);
        result.extend_from_slice(&self.reserved);
        result
    }
}

pub struct ServiceGetSoftwareVersionResponse {
    pub status: u8,
    pub len: u32,
    pub version: String,
}

impl FromBytes for ServiceGetSoftwareVersionResponse {
    fn from_bytes(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < 5 {
            return Err(ParseError::InsufficientData { expected: 5, actual: data.len() });
        }
        
        let status = data[0];
        let len = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
        
        if data.len() < 5 + len as usize {
            return Err(ParseError::InsufficientData { expected: 5 + len as usize, actual: data.len() });
        }
        
        let version_bytes = &data[5..5 + len as usize];
        let version = String::from_utf8(version_bytes.to_vec())
            .map_err(|e| ParseError::InvalidData(format!("Invalid UTF-8 in version string: {}", e)))?;
        
        Ok(Self { status, len, version })
    }
}

// Response structures
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceResponse {
    pub status: u8,
    pub data: Vec<u8>,
}

impl ServiceResponse {
    pub fn success(data: Vec<u8>) -> Self {
        Self { status: 0x00, data }
    }
    
    pub fn error(error_code: u8) -> Self {
        Self { status: error_code, data: Vec::new() }
    }
}

impl ToBytes for ServiceResponse {
    fn to_bytes(&self) -> Vec<u8> {
        let mut result = vec![self.status];
        result.extend_from_slice(&self.data);
        result
    }
}

/// Error types for service parsing
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceError {
    UnknownServiceId(u32),
    ParseError(ParseError),
    HandlerError(String),
}

impl From<ParseError> for ServiceError {
    fn from(error: ParseError) -> Self {
        ServiceError::ParseError(error)
    }
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceError::UnknownServiceId(id) => write!(f, "Unknown service ID: 0x{:02X}", id),
            ServiceError::ParseError(err) => write!(f, "Parse error: {}", err),
            ServiceError::HandlerError(msg) => write!(f, "Handler error: {}", msg),
        }
    }
}

impl std::error::Error for ServiceError {}

pub type ServiceResult<T> = Result<T, ServiceError>;

/// Enhanced trait with parsed request handling
pub trait ServiceHandler {
    // Typed service handlers
    fn handle_set_log_level(&mut self, request: ServiceSetLogLevelRequest) -> ServiceResult<ServiceResponse> {
        Err(ServiceError::HandlerError("SetLogLevel not implemented".to_string()))
    }
    
    fn handle_set_trace_status(&mut self, request: ServiceSetTraceStatusRequest) -> ServiceResult<ServiceResponse> {
        Err(ServiceError::HandlerError("SetTraceStatus not implemented".to_string()))
    }
    
    fn handle_get_log_info(&mut self, response: ServiceGetLogInfoResponse) -> ServiceResult<ServiceResponse> {
        Err(ServiceError::HandlerError("GetLogInfo not implemented".to_string()))
    }
    
    fn handle_get_default_log_level(&mut self) -> ServiceResult<ServiceResponse> {
        Err(ServiceError::HandlerError("GetDefaultLogLevel not implemented".to_string()))
    }
    
    fn handle_store_configuration(&mut self) -> ServiceResult<ServiceResponse> {
        Err(ServiceError::HandlerError("StoreConfiguration not implemented".to_string()))
    }
    
    fn handle_restore_to_factory_default(&mut self) -> ServiceResult<ServiceResponse> {
        Err(ServiceError::HandlerError("RestoreToFactoryDefault not implemented".to_string()))
    }
    
    fn handle_set_message_filtering(&mut self, request: ServiceSetMessageFilteringRequest) -> ServiceResult<ServiceResponse> {
        Err(ServiceError::HandlerError("SetMessageFiltering not implemented".to_string()))
    }
    
    fn handle_set_default_log_level(&mut self, request: ServiceSetDefaultLogLevelRequest) -> ServiceResult<ServiceResponse> {
        Err(ServiceError::HandlerError("SetDefaultLogLevel not implemented".to_string()))
    }
    
    fn handle_set_default_trace_status(&mut self, new_status: u8) -> ServiceResult<ServiceResponse> {
        Err(ServiceError::HandlerError("SetDefaultTraceStatus not implemented".to_string()))
    }
    
    fn handle_get_software_version(&mut self, version: &String) -> ServiceResult<ServiceResponse> {
        Err(ServiceError::HandlerError("GetSoftwareVersion not implemented".to_string()))
    }
    
    fn handle_get_default_trace_status(&mut self) -> ServiceResult<ServiceResponse> {
        Err(ServiceError::HandlerError("GetDefaultTraceStatus not implemented".to_string()))
    }
    
    fn handle_get_log_channel_names(&mut self) -> ServiceResult<ServiceResponse> {
        Err(ServiceError::HandlerError("GetLogChannelNames not implemented".to_string()))
    }
    
    fn handle_get_trace_status(&mut self, apid: [u8; DLT_ID_SIZE], ctid: [u8; DLT_ID_SIZE]) -> ServiceResult<ServiceResponse> {
        Err(ServiceError::HandlerError("GetTraceStatus not implemented".to_string()))
    }
    
    fn handle_swc_injection(&mut self, service_id: u32, payload: &[u8]) -> ServiceResult<ServiceResponse> {
        Err(ServiceError::HandlerError("SWC Injection not implemented".to_string()))
    }
    
    /// Handle unknown service IDs
    fn handle_unknown_service(&mut self, service_id: u32, payload: &[u8]) -> ServiceResult<ServiceResponse> {
        Err(ServiceError::UnknownServiceId(service_id))
    }
}

/// Service message structure
#[derive(Debug, Clone)]
pub struct ServiceMessage {
    pub service_id: u32,
    pub payload: Vec<u8>,
}

impl ServiceMessage {
    pub fn new(service_id: u32, payload: Vec<u8>) -> Self {
        Self { service_id, payload }
    }
    
    pub fn service_type(&self) -> Option<ServiceType> {
        ServiceType::from_u32(self.service_id)
    }
}

/// Main service parser with automatic parsing
pub struct ServiceParser {
    stats: HashMap<ServiceType, u64>,
}

impl ServiceParser {
    pub fn new() -> Self {
        Self {
            stats: HashMap::new(),
        }
    }
    
    /// Handle a service message with automatic parsing
    pub fn handle_message<H: ServiceHandler>(
        &mut self,
        handler: &mut H,
        message: ServiceMessage,
    ) -> ServiceResult<Vec<u8>> {
        if let Some(service_type) = message.service_type() {
            *self.stats.entry(service_type).or_insert(0) += 1;
            
            let response = match service_type {
                ServiceType::SetLogLevel => {
                    let request = ServiceSetLogLevelRequest::from_bytes(&message.payload)?;
                    handler.handle_set_log_level(request)?
                }
                ServiceType::SetTraceStatus => {
                    let request = ServiceSetTraceStatusRequest::from_bytes(&message.payload)?;
                    handler.handle_set_trace_status(request)?
                }
                ServiceType::GetLogInfo => {            
                    let response = ServiceGetLogInfoResponse::from_bytes(&message.payload)?;       
                    handler.handle_get_log_info(response)?
                }
                ServiceType::GetDefaultLogLevel => {
                    handler.handle_get_default_log_level()?
                }
                ServiceType::StoreConfiguration => {
                    handler.handle_store_configuration()?
                }
                ServiceType::RestoreToFactoryDefault => {
                    handler.handle_restore_to_factory_default()?
                }
                ServiceType::SetMessageFiltering => {
                    let request = ServiceSetMessageFilteringRequest::from_bytes(&message.payload)?;
                    handler.handle_set_message_filtering(request)?
                }
                ServiceType::SetDefaultLogLevel => {
                    let request = ServiceSetDefaultLogLevelRequest::from_bytes(&message.payload)?;
                    handler.handle_set_default_log_level(request)?
                }
                ServiceType::SetDefaultTraceStatus => {
                    if message.payload.is_empty() {
                        return Err(ServiceError::ParseError(ParseError::InsufficientData { expected: 1, actual: 0 }));
                    }
                    handler.handle_set_default_trace_status(message.payload[0])?
                }
                ServiceType::GetSoftwareVersion => {
                    if message.payload.len() < 4 {
                        return Err(ServiceError::ParseError(ParseError::InsufficientData { expected: 4, actual: message.payload.len() }));
                    }
                    let software_version = ServiceGetSoftwareVersionResponse::from_bytes(&message.payload)?;

                    handler.handle_get_software_version(&software_version.version)?
                }
                ServiceType::GetDefaultTraceStatus => {
                    handler.handle_get_default_trace_status()?
                }
                ServiceType::GetLogChannelNames => {
                    handler.handle_get_log_channel_names()?
                }
                ServiceType::GetTraceStatus => {
                    if message.payload.len() < DLT_ID_SIZE * 2 {
                        return Err(ServiceError::ParseError(ParseError::InsufficientData { 
                            expected: DLT_ID_SIZE * 2, 
                            actual: message.payload.len() 
                        }));
                    }
                    let mut apid = [0u8; DLT_ID_SIZE];
                    let mut ctid = [0u8; DLT_ID_SIZE];
                    apid.copy_from_slice(&message.payload[0..DLT_ID_SIZE]);
                    ctid.copy_from_slice(&message.payload[DLT_ID_SIZE..DLT_ID_SIZE*2]);
                    handler.handle_get_trace_status(apid, ctid)?
                }
                ServiceType::SWCInjection => {
                    handler.handle_swc_injection(message.service_id, &message.payload)?
                }
                // Add cases for remaining services...
                _ => {
                    return Err(ServiceError::HandlerError("Service handler not implemented".to_string()));
                }
            };
            
            Ok(response.to_bytes())
        } else {
            let response = handler.handle_unknown_service(message.service_id, &message.payload)?;
            Ok(response.to_bytes())
        }
    }
    
    pub fn parse_raw_message(&self, data: &[u8]) -> ServiceResult<ServiceMessage> {
        if data.is_empty() {
            return Err(ServiceError::ParseError(ParseError::InsufficientData { expected: 1, actual: 0 }));
        }
        
        // Extract 32-bit service_id from first 4 bytes
        let service_id_bytes = &data[0..4];
        let service_id = u32::from_le_bytes([
            service_id_bytes[0],
            service_id_bytes[1], 
            service_id_bytes[2],
            service_id_bytes[3]
        ]);
        let payload = data[4..].to_vec();
        
        Ok(ServiceMessage::new(service_id, payload))
    }
    
    pub fn get_stats(&self) -> &HashMap<ServiceType, u64> {
        &self.stats
    }
    
    pub fn reset_stats(&mut self) {
        self.stats.clear();
    }
}

impl Default for ServiceParser {
    fn default() -> Self {
        Self::new()
    }
}

// Example usage and tests
#[cfg(test)]
mod tests {
    use super::*;

    struct MyServiceHandler;

    impl ServiceHandler for MyServiceHandler {
        fn handle_set_log_level(&mut self, request: ServiceSetLogLevelRequest) -> ServiceResult<ServiceResponse> {
            println!("Setting log level to {} for APID: {:?}, CTID: {:?}", 
                    request.new_log_level, 
                    std::str::from_utf8(&request.apid).unwrap_or("invalid"),
                    std::str::from_utf8(&request.ctid).unwrap_or("invalid"));
            Ok(ServiceResponse::success(vec![]))
        }

        fn handle_get_log_info(&mut self, response: ServiceGetLogInfoResponse) -> ServiceResult<ServiceResponse> {
            println!("Get log info");
            println!("{:?}", response);
            Ok(ServiceResponse::success(vec![]))
        }
        
        fn handle_get_software_version(&mut self, version: &String) -> ServiceResult<ServiceResponse> {
            println!("Getting software version");
            println!("Software Version: {}", version);
            Ok(ServiceResponse::success(b"v1.2.3".to_vec()))
        }
        
        fn handle_store_configuration(&mut self) -> ServiceResult<ServiceResponse> {
            println!("Storing configuration");
            Ok(ServiceResponse::success(vec![]))
        }
    }

    #[test]
    fn test_structured_service_handling() {
        let mut parser = ServiceParser::new();
        let mut handler = MyServiceHandler;

        // Test SetLogLevel with structured data
        let mut payload = Vec::new();
        payload.extend_from_slice(b"APP1"); // APID
        payload.extend_from_slice(b"CTX1"); // CTID  
        payload.push(0x02); // new_log_level
        payload.extend_from_slice(b"RES1"); // reserved
        
        
        let get_log_info_payload = vec![7, 1, 0, 76, 79, 71, 0, 1, 0, 84, 83, 49, 0, 255, 255, 27, 0, 84, 101, 115, 116, 32, 67, 111, 110, 116, 101, 120, 116, 49, 32, 102, 111, 114, 32, 105, 110, 106, 101, 99, 116, 105, 111, 110, 28, 0, 84, 101, 115, 116, 32, 65, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 32, 102, 111, 114, 32, 76, 111, 103, 103, 105, 110, 103, 114, 101, 109, 111];
        let message = ServiceMessage::new(0x03, get_log_info_payload);
        let result = parser.handle_message(&mut handler, message).unwrap();
        assert!(result.is_empty());

        let message = ServiceMessage::new(0x01, payload);
        let result = parser.handle_message(&mut handler, message);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_request_parsing() {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"APP1");
        payload.extend_from_slice(b"CTX1");
        payload.push(0x03);
        payload.extend_from_slice(b"RES1");

        
        let request = ServiceSetLogLevelRequest::from_bytes(&payload).unwrap();
        assert_eq!(request.apid, *b"APP1");
        assert_eq!(request.ctid, *b"CTX1");
        assert_eq!(request.new_log_level, 0x03);
        assert_eq!(request.reserved, *b"RES1");
        
        // Test round-trip serialization
        let serialized = request.to_bytes();
        assert_eq!(serialized, payload);
    }

    #[test]
    fn test_binary_service_message_creation() {
        // Test ServiceMessage with various binary patterns
        let test_cases = vec![
            (0x01, vec![]), // Empty payload
            (0xFF, vec![0x00]), // Max service ID with null payload
            (0x00, vec![0xFF, 0xFE, 0xFD]), // Min service ID with high byte payload
            (0x7F, vec![0x80, 0x81, 0x82]), // Boundary service ID
        ];

        for (service_id, payload) in test_cases {
            let message = ServiceMessage::new(service_id, payload.clone());
            assert_eq!(message.service_id, service_id);
            assert_eq!(message.payload, payload);
            
            // Test service type detection
            let service_type = message.service_type();
            if ServiceType::from_u32(service_id).is_some() {
                assert!(service_type.is_some());
            } else {
                assert!(service_type.is_none());
            }
        }
    }
}