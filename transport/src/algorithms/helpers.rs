//! Contains helper functions to implement algorithms and check their validity.

use crate::errors::InvalidNameError;

/// Checks if the given domain name is valid.
fn is_valid_domain(domain: &str) -> bool {
    for label in domain.split('.') {
        if label.is_empty() {
            return false;
        }
        if label.starts_with('-') {
            return false;
        }
        if label.ends_with('-') {
            return false;
        }
        if label
            .chars()
            .any(|c| !c.is_ascii_alphanumeric() && c != '-')
        {
            return false;
        }
    }

    true
}

/// Checks of the given algorithm name is a valid algorithm name according to
/// [RFC4351](https://tools.ietf.org/html/rfc4251#section-6).
pub(crate) fn validate_algorithm_name(name: &str) -> Result<(), InvalidNameError> {
    if name.is_empty() {
        return Err(InvalidNameError::EmptyName);
    }

    if name.len() > 64 {
        return Err(InvalidNameError::TooLong);
    }

    if let Some(result) = name.chars().find_map(|c| {
        if c == ',' {
            Some(Err(InvalidNameError::CommaUsed))
        } else if !c.is_ascii() {
            Some(Err(InvalidNameError::NonAscii(c)))
        } else if c.is_ascii_whitespace() {
            Some(Err(InvalidNameError::Whitespace(c)))
        } else if !c.is_ascii_graphic() {
            Some(Err(InvalidNameError::NonPrintable(c)))
        } else {
            None
        }
    }) {
        return result;
    }

    let mut iter = name.split('@');

    iter.next();

    if let Some(domain) = iter.next() {
        if !is_valid_domain(domain) {
            return Err(InvalidNameError::InvalidDomain);
        }
    }

    if iter.next().is_some() {
        return Err(InvalidNameError::TooManyAtSymbols);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_name() {
        assert_eq!(validate_algorithm_name("3des-cbc"), Ok(()));
        assert_eq!(validate_algorithm_name("aes128-cbc"), Ok(()));
        assert_eq!(
            validate_algorithm_name("some-algorithm@example123.com"),
            Ok(())
        );
        assert_eq!(validate_algorithm_name("some-algorithm@com"), Ok(()));

        assert_eq!(
            validate_algorithm_name("test@-dash.prefix"),
            Err(InvalidNameError::InvalidDomain)
        );
        assert_eq!(
            validate_algorithm_name("test@trailing-.dash"),
            Err(InvalidNameError::InvalidDomain)
        );
        assert_eq!(
            validate_algorithm_name("test@empty..label"),
            Err(InvalidNameError::InvalidDomain)
        );
        assert_eq!(
            validate_algorithm_name("test@example.com@double-at.not-allowed"),
            Err(InvalidNameError::TooManyAtSymbols)
        );
        assert_eq!(
            validate_algorithm_name("this-is-a-very-long-algorithm-name-that-will-exceed-the-permitted-length-by-quite-a-bit-and-therefore-fail-the-test"),
            Err(InvalidNameError::TooLong)
        );
        assert_eq!(
            validate_algorithm_name("commas,are,not,allowed"),
            Err(InvalidNameError::CommaUsed)
        );
        assert_eq!(
            validate_algorithm_name(""),
            Err(InvalidNameError::EmptyName)
        );
        assert_eq!(
            validate_algorithm_name("non\u{f4}ascii-not-allowed"),
            Err(InvalidNameError::NonAscii('\u{f4}'))
        );
        assert_eq!(
            validate_algorithm_name("control\x11ascii-not-allowed"),
            Err(InvalidNameError::NonPrintable('\x11'))
        );
        assert_eq!(
            validate_algorithm_name("whitespace not allowed"),
            Err(InvalidNameError::Whitespace(' '))
        );
    }
}
