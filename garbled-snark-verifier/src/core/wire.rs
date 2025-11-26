use serde::{Deserialize, Serialize};

use crate::core::{s::S, utils::DELTA};

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct Wire {
    // garble
    pub label: Option<S>,
    // evaluate
    pub value: Option<bool>,
    // id in sub-circuit wire list.
    // should be removed in case of not using sub-circuits
    pub id: Option<u32>,
}

impl Default for Wire {
    fn default() -> Self {
        Self::new(None)
    }
}

impl Wire {
    #[cfg(feature = "garbled")]
    pub fn new(id: Option<u32>) -> Self {
        let label = Some(S::random());
        Self { label, value: None, id }
    }

    #[cfg(not(feature = "garbled"))]
    pub fn new(id: Option<u32>) -> Self {
        Self { label: None, value: None, id }
    }

    pub fn select(&self, selector: bool) -> S {
        if !selector { self.label.unwrap() } else { self.label.unwrap() ^ DELTA }
    }

    pub fn get_value(&self) -> bool {
        assert!(self.value.is_some());
        self.value.unwrap()
    }

    pub fn get_label(&self) -> S {
        assert!(self.label.is_some());
        self.label.unwrap()
    }

    pub fn set_label(&mut self, label: S) {
        self.label = Some(label);
    }

    pub fn set(&mut self, bit: bool) {
        assert!(self.value.is_none());
        self.value = Some(bit);
    }
}
