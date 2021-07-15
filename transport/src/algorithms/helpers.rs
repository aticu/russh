//! Contains helper functions to implement algorithms and check their validity.

use russh_definitions::algorithms::Algorithm;

use crate::errors::{InvalidAlgorithmError, InvalidNameError};

/// Checks if the given domain name is valid.
fn is_valid_domain(domain: &str) -> bool {
    for label in domain.split('.') {
        if label.len() == 0 {
            return false;
        }
        if label.chars().next() == Some('-') {
            return false;
        }
        if label.chars().last() == Some('-') {
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
fn valid_algorithm_name(name: &str) -> Result<(), InvalidNameError> {
    if name.is_empty() {
        Err(InvalidNameError::EmptyName)
    } else if name.len() > 64 {
        Err(InvalidNameError::TooLong)
    } else if let Some(result) = name.chars().find_map(|c| {
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
        result
    } else {
        let mut iter = name.split('@');

        iter.next();

        if let Some(domain) = iter.next() {
            if !is_valid_domain(domain) {
                return Err(InvalidNameError::InvalidDomain);
            }
        }

        if iter.next().is_none() {
            Ok(())
        } else {
            Err(InvalidNameError::TooManyAtSymbols)
        }
    }
}

/// Attempts to validate the validity of an algorithm implementation.
pub(crate) fn is_valid_algorithm(algorithm: &dyn Algorithm) -> Result<(), InvalidAlgorithmError> {
    valid_algorithm_name(algorithm.name()).map_err(|err| InvalidAlgorithmError::InvalidName {
        algorithm_name: algorithm.name().into(),
        algorithm_category: algorithm.category(),
        name_error: err,
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_name() {
        assert_eq!(valid_algorithm_name("3des-cbc"), Ok(()));
        assert_eq!(valid_algorithm_name("aes128-cbc"), Ok(()));
        assert_eq!(
            valid_algorithm_name("some-algorithm@example123.com"),
            Ok(())
        );
        assert_eq!(valid_algorithm_name("some-algorithm@com"), Ok(()));

        assert_eq!(
            valid_algorithm_name("test@-dash.prefix"),
            Err(InvalidNameError::InvalidDomain)
        );
        assert_eq!(
            valid_algorithm_name("test@trailing-.dash"),
            Err(InvalidNameError::InvalidDomain)
        );
        assert_eq!(
            valid_algorithm_name("test@empty..label"),
            Err(InvalidNameError::InvalidDomain)
        );
        assert_eq!(
            valid_algorithm_name("test@example.com@double-at.not-allowed"),
            Err(InvalidNameError::TooManyAtSymbols)
        );
        assert_eq!(
            valid_algorithm_name("this-is-a-very-long-algorithm-name-that-will-exceed-the-permitted-length-by-quite-a-bit-and-therefore-fail-the-test"),
            Err(InvalidNameError::TooLong)
        );
        assert_eq!(
            valid_algorithm_name("commas,are,not,allowed"),
            Err(InvalidNameError::CommaUsed)
        );
        assert_eq!(valid_algorithm_name(""), Err(InvalidNameError::EmptyName));
        assert_eq!(
            valid_algorithm_name("non\u{f4}ascii-not-allowed"),
            Err(InvalidNameError::NonAscii('\u{f4}'))
        );
        assert_eq!(
            valid_algorithm_name("control\x11ascii-not-allowed"),
            Err(InvalidNameError::NonPrintable('\x11'))
        );
        assert_eq!(
            valid_algorithm_name("whitespace not allowed"),
            Err(InvalidNameError::Whitespace(' '))
        );
    }
}
