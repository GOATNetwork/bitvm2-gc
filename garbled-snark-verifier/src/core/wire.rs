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
        //let label1 = S::random();
        //Self { label0: Some(label0), label1: Some(label1) }
        Self { label, value: None }
    }

    #[cfg(not(feature = "garbled"))]
    pub fn new() -> Self {
        //Self { label0: None, label1: None, value: None, label: None }
        Self { label: None, value: None }
    }

    pub fn select(&self, selector: bool) -> S {
        //if selector { self.label1.unwrap() } else { self.label0.unwrap() }
        if selector { self.label.unwrap() } else { self.label.unwrap() ^ DELTA }
    }

    //pub fn select_hash(&self, selector: bool) -> S {
    //    if selector { (self.label.unwrap() ^ DELTA).hash() } else { self.label.unwrap().hash() }
    //}

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

    //pub fn set2(&mut self, bit: bool, label: S) {
    //    assert!(self.value.is_none());
    //    self.value = Some(bit);
    //    self.label = Some(label);
    //}
}
