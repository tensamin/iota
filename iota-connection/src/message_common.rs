use base64::{Engine as _, engine::general_purpose::STANDARD};
use iota_storage::util::chat_files::{FileStatus, MessageFile};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use mtp::type_map::TypeMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub use iota_util::mtp_compat::{MtpFieldError, OptionalDataValueExt, RequiredCommunicationFields};

pub use tau::{CommunicationResponseExt, data_i64, data_string};

/// Handler requests must carry the map negotiated by their transport.
pub fn error_response(request: &CommunicationValue, kind: CommunicationType) -> CommunicationValue {
    let type_map = request
        .type_map()
        .expect("handler request has a negotiated type map");
    tau::error_response(request, kind, type_map)
}

/// Encode nested values for handlers that explicitly emit the latest protocol.
/// Negotiated-map encoding uses tau::typed_container with its explicit map.
pub fn typed_container(
    items: Vec<(DataType, DataValue)>,
) -> Result<DataValue, tau::ProtocolValueError> {
    tau::typed_container(&TypeMap::latest(), items)
}

#[derive(Debug, Clone)]
pub struct ChatSecretRecipient {
    pub user_id: String,
    pub encrypted_secret: Vec<u8>,
    pub kem_ciphertext: Vec<u8>,
}

pub fn recipient_from_value(value: &DataValue, type_map: &TypeMap) -> Option<ChatSecretRecipient> {
    let user_id = value
        .get_field(DataType::UserId.try_to_id(type_map)?)?
        .as_str()
        .map(|s| s.to_string())
        .or_else(|| {
            value
                .get_field(DataType::UserId.try_to_id(type_map)?)?
                .as_number()
                .map(|n| n.to_string())
        })?;
    let encrypted_secret = value
        .get_field(DataType::EncryptedSecret.try_to_id(type_map)?)?
        .as_bytes()?;
    let kem_ciphertext = value
        .get_field(DataType::KemCiphertext.try_to_id(type_map)?)?
        .as_bytes()?;

    Some(ChatSecretRecipient {
        user_id,
        encrypted_secret,
        kem_ciphertext,
    })
}

pub fn chat_secret_recipients(cv: &CommunicationValue) -> Option<Vec<ChatSecretRecipient>> {
    let type_map = cv.type_map()?;
    let recipients = cv
        .payload()
        .get_field(DataType::Recipients.try_to_id(type_map)?)?
        .as_array()?;
    let parsed = recipients
        .iter()
        .map(|value| recipient_from_value(value, type_map))
        .collect::<Option<Vec<_>>>()?;

    if parsed.is_empty() {
        None
    } else {
        Some(parsed)
    }
}

pub const MAX_MESSAGE_FILES: usize = 32;

pub const MAX_MESSAGE_BODY_BYTES: usize = 128 * 1024;

fn file_status_name(status: FileStatus) -> &'static str {
    match status {
        FileStatus::Uploading => "uploading",
        FileStatus::Cancelled => "cancelled",
        FileStatus::Failed => "failed",
    }
}

pub fn message_files(frame: &CommunicationValue) -> Option<Vec<MessageFile>> {
    let Some(value) = frame.get_data(DataType::Files) else {
        return Some(Vec::new());
    };
    let map = frame.type_map()?;
    let (content, status) = (
        DataType::Content.try_to_id(map)?,
        DataType::Status.try_to_id(map)?,
    );
    let entries = value.as_array_slice()?;
    if entries.len() > MAX_MESSAGE_FILES {
        return None;
    }
    entries
        .iter()
        .map(|entry| {
            let fields = entry.container_entries()?;
            let count = |key| fields.iter().filter(|(field, _)| *field == key).count();
            if count(content) != 1
                || count(status) > 1
                || count(content) + count(status) != fields.len()
            {
                return None;
            }
            let reference = entry.get_field(content)?.as_str()?;
            STANDARD.decode(reference).ok()?;
            let status = match entry.get_field(status) {
                None => None,
                Some(value) => Some(match value.as_str()? {
                    "uploading" => FileStatus::Uploading,
                    "cancelled" => FileStatus::Cancelled,
                    "failed" => FileStatus::Failed,
                    _ => return None,
                }),
            };
            Some(MessageFile {
                reference: reference.to_owned(),
                status,
            })
        })
        .collect()
}

pub fn message_body(frame: &CommunicationValue) -> Option<(Option<String>, Vec<MessageFile>)> {
    let content = match frame.get_data(DataType::Content) {
        Some(value) => Some(value.as_string()?),
        None => None,
    };
    let files = message_files(frame)?;

    let size = serde_json::to_string(&content).ok()?.len()
        + files.iter().map(|file| file.reference.len()).sum::<usize>();
    (size <= MAX_MESSAGE_BODY_BYTES && (content.is_some() || !files.is_empty()))
        .then_some((content, files))
}

pub fn message_files_value(
    type_map: &TypeMap,
    files: &[MessageFile],
) -> Result<DataValue, tau::ProtocolValueError> {
    files
        .iter()
        .map(|file| {
            let mut fields = vec![(DataType::Content, DataValue::Str(file.reference.clone()))];
            if let Some(status) = file.status {
                fields.push((
                    DataType::Status,
                    DataValue::Str(file_status_name(status).into()),
                ));
            }
            tau::typed_container(type_map, fields)
        })
        .collect::<Result<_, _>>()
        .map(DataValue::Array)
}

pub fn now_millis_i64() -> i64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    i64::try_from(millis).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::error_response;
    use mtp::codec::{CommunicationType, CommunicationValue};

    #[test]
    fn error_response_preserves_an_absent_request_id() {
        let request = CommunicationValue::new(CommunicationType::GetChats)
            .without_id()
            .with_sender(42);
        let response = error_response(&request, CommunicationType::ErrorInvalidData);

        assert_eq!(response.id(), None);
        assert_eq!(response.receiver(), Some(42));
    }

    #[test]
    fn error_response_copies_an_existing_request_id() {
        let request = CommunicationValue::new(CommunicationType::GetChats)
            .with_id(7)
            .with_sender(42);
        let response = error_response(&request, CommunicationType::ErrorInvalidData);

        assert_eq!(response.id(), Some(7));
        assert_eq!(response.receiver(), Some(42));
    }
}
