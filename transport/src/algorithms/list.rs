//! Defines a list to hold all algorithms of the same type and return the currently chosen one.

use std::borrow::Cow;

use super::helpers::validate_algorithm_name;
use crate::errors::InvalidNameError;

/// A trait to abstract over algorithms being named.
///
/// This is mainly used to identify and find algorithms by their name.
pub(crate) trait Nameable {
    /// Returns the name of `self`.
    ///
    /// The assigned name of a value must remain the same for the algorithm list to work correctly.
    fn name(&self) -> &'static str;
}

/// Specifies where to add an algorithm into the list.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum AddIn {
    /// Adds an algorithm to the front of the list, giving it priority over existing algorithms.
    Front,
    /// Adds an algorithm to the back of the list, giving existing algorithms priority over it.
    Back,
    /// Replaces an algorithm of the same name in the list at its position.
    ///
    /// If no such algorithm exists, the algorithm is not inserted into the list.
    CurrentPosition,
}

/// A list holding all algorithms of the same type and storing which one is currently active.
#[derive(Debug)]
pub(crate) struct AlgorithmList<Entry: Nameable> {
    /// The list of algorithm entries.
    list: Vec<Entry>,
    /// The index of the currently chosen algorithm.
    current: Option<usize>,
}

impl<Entry: Nameable> AlgorithmList<Entry> {
    /// Creates a new empty algorithm list.
    pub(crate) fn new() -> AlgorithmList<Entry> {
        AlgorithmList {
            list: Vec::new(),
            current: None,
        }
    }

    /// Adds an entry describing an algorithm into the list.
    ///
    /// Read the documentation of [`AddIn`] to learn more about where the entry can be added into
    /// the list.
    pub(crate) fn add_raw(
        &mut self,
        entry: Entry,
        position: AddIn,
    ) -> Result<&mut Self, InvalidNameError> {
        validate_algorithm_name(entry.name())?;

        match position {
            AddIn::Back | AddIn::Front => {
                if let Some(idx) = self.find_index(entry.name()) {
                    self.list.remove(idx);
                }

                self.list.insert(
                    match position {
                        AddIn::Back => self.list.len(),
                        AddIn::Front => 0,
                        _ => unreachable!(),
                    },
                    entry,
                );
            }
            AddIn::CurrentPosition => {
                if let Some(idx) = self.find_index(entry.name()) {
                    self.list[idx] = entry;
                }
            }
        }

        Ok(self)
    }

    /// Adds a new algorithm to the front of the list.
    ///
    /// This gives it priority over algorithms already present in the list.
    ///
    /// If another algorithm with the same name is already present in the list, it is removed prior
    /// to adding the new algorithm.
    pub(crate) fn add<Alg: Into<Entry>>(
        &mut self,
        new_alg: Alg,
        position: AddIn,
    ) -> Result<&mut Self, InvalidNameError> {
        self.add_raw(new_alg.into(), position)
    }

    /// Returns `true` if and only if the list doesn't contain any items.
    pub(crate) fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// Clears all algorithms from the list.
    pub(crate) fn clear(&mut self) {
        self.list.clear();
        self.current = None;
    }

    /// Returns `true` if and only if an algorithm named `name` is contained in the list.
    pub(crate) fn contains_algorithm(&self, name: &str) -> bool {
        self.find_index(name).is_some()
    }

    /// Finds the index of the algorithm with the given name, if it is present in the list.
    fn find_index(&self, name: &str) -> Option<usize> {
        self.list.iter().position(|entry| entry.name() == name)
    }

    /// Chooses the algorithm with the given name.
    pub(crate) fn choose(&mut self, name: &str) {
        if let Some(idx) = self.find_index(name) {
            self.current = Some(idx);
        }
    }

    /// Returns a reference to the algorithm named `name`, if it exists in the list.
    pub(crate) fn algorithm(&self, name: &str) -> Option<&Entry> {
        if let Some(idx) = self.find_index(name) {
            Some(&self.list[idx])
        } else {
            None
        }
    }

    /// Returns a mutable reference to the algorithm named `name`, if it exists in the list.
    pub(crate) fn algorithm_mut(&mut self, name: &str) -> Option<&mut Entry> {
        if let Some(idx) = self.find_index(name) {
            Some(&mut self.list[idx])
        } else {
            None
        }
    }

    /// Returns the currently chosen algorithm.
    ///
    /// If no algorithm was previously chosen, the algorithm named "none" will be chosen for future
    /// calls and returned.
    ///
    /// # Panics
    /// This function panics if no algorithm was previously chosen and no algorithm named "none" is
    /// present in the list.
    pub(crate) fn current(&mut self) -> &mut Entry {
        if let Some(idx) = self.current.or_else(|| {
            self.choose("none");
            self.current
        }) {
            &mut self.list[idx]
        } else {
            panic!("no algorithm was chosen and no \"none\" algorithm was present");
        }
    }

    /// Creates a list of all algorithm names.
    pub(crate) fn to_name_list(&self, include_none: bool) -> Vec<Cow<'static, str>> {
        self.list
            .iter()
            .map(|alg| Cow::Borrowed(alg.name()))
            .filter(|name| include_none || name != "none")
            .collect()
    }
}
