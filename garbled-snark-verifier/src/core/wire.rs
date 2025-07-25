use serde::{Deserialize, Serialize};

use crate::core::{s::S, utils::DELTA};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Wire {
    // garble
    pub label: Option<S>,
    // evaluate
    pub value: Option<bool>,
}

impl Default for Wire {
    fn default() -> Self {
        Self::new()
    }
}

impl Wire {
    #[cfg(feature = "garbled")]
    pub fn new() -> Self {
        let label = Some(S::random());
        Self { label, value: None }
    }

    #[cfg(not(feature = "garbled"))]
    pub fn new() -> Self {
        Self { label: None, value: None }
    }

    pub fn select(&self, selector: bool) -> S {
        if selector { self.label.unwrap() } else { self.label.unwrap() ^ DELTA }
    }

    pub fn get_value(&self) -> bool {
        assert!(self.value.is_some());
        self.value.unwrap()
    }

    pub fn get_label(&self) -> S {
        assert!(self.value.is_some());
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
