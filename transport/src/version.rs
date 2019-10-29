//! Contains structures to deal with versioning.

use std::{borrow::Cow, fmt};

use crate::{constants::PROTOCOL_VERSION, errors::IllegalVersionError};

/// Contains version information about one participant of the connection.
#[derive(Debug, PartialEq, Eq)]
pub struct VersionInformation {
    /// The version of the protocol.
    protocol_version: Cow<'static, str>,
    /// The version of the software.
    software_version: Cow<'static, str>,
}

impl VersionInformation {
    /// Creates new version information.
    pub fn new<V: Into<Cow<'static, str>>>(
        software_version: V,
    ) -> Result<VersionInformation, IllegalVersionError> {
        let software_version = software_version.into();

        if let Some(err) = software_version_error(&software_version) {
            Err(err)
        } else {
            Ok(VersionInformation {
                protocol_version: PROTOCOL_VERSION.into(),
                software_version,
            })
        }
    }

    /// Creates new version information without performing validity checks.
    ///
    /// This is used for the arriving version from the partner of the connection.
    pub(crate) fn new_unchecked<V1: Into<Cow<'static, str>>, V2: Into<Cow<'static, str>>>(
        protocol_version: V1,
        software_version: V2,
    ) -> VersionInformation {
        VersionInformation {
            protocol_version: protocol_version.into(),
            software_version: software_version.into(),
        }
    }

    /// Returns the version of the protocol.
    pub fn protocol_version(&self) -> &str {
        &self.protocol_version
    }

    /// Returns the version of the software.
    pub fn software_version(&self) -> &str {
        &self.software_version
    }

    /// Sets the version of the protocol.
    pub fn set_protocol_version<V: Into<Cow<'static, str>>>(&mut self, new_version: V) {
        self.protocol_version = new_version.into();
    }

    /// Sets the version of the software.
    pub fn set_software_version<V: Into<Cow<'static, str>>>(&mut self, new_version: V) {
        self.software_version = new_version.into();
    }
}

impl Default for VersionInformation {
    fn default() -> VersionInformation {
        let name = env!("CARGO_PKG_NAME");
        let version = env!("CARGO_PKG_VERSION");

        let mut software_version_bytes =
            format!("{name}@{version}", name = name, version = version).into_bytes();

        for c in software_version_bytes.iter_mut() {
            if *c == b'-' {
                *c = b'_';
            }
        }

        let mut software_version = String::from_utf8(software_version_bytes)
            .expect("replacing '-' with '_' should not break string invariants");

        software_version.retain(|c| c.is_ascii_graphic() && c != '-');

        VersionInformation::new(software_version).expect("own software version should be legal")
    }
}

impl fmt::Display for VersionInformation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "SSH-{protoversion}-{softwareversion}",
            protoversion = self.protocol_version(),
            softwareversion = self.software_version()
        )
    }
}

/// Checks if the version is a legal software version string.
fn software_version_error(version: &str) -> Option<IllegalVersionError> {
    version.char_indices().find_map(|(index, c)| {
        if !c.is_ascii() {
            Some(IllegalVersionError::NonAscii(index))
        } else if c.is_whitespace() {
            Some(IllegalVersionError::Whitespace(index))
        } else if !c.is_ascii_graphic() {
            Some(IllegalVersionError::NonPrintable(index))
        } else if c == '-' {
            Some(IllegalVersionError::Minus(index))
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legal_software_version() {
        let version_info = VersionInformation::default();
        let version = version_info.software_version();

        assert_eq!(software_version_error(version), None);
    }
}
