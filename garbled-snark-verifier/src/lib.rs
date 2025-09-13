pub mod circuits;
pub mod core;

pub mod bag {
    pub use crate::core::circuit::Circuit;
    pub use crate::core::gate::Gate;
    pub use crate::core::gate::GateCount;
    pub use crate::core::s::S;
    pub use crate::core::wire::Wire;
    use crate::core::wire::WireId;
    pub use std::{cell::RefCell, rc::Rc};

    pub type Wirex = Rc<RefCell<Wire>>;
    pub type Wires = Vec<Wirex>;
    pub type WireIds = Vec<WireId>;
    pub fn new_wirex() -> Wirex {
        Rc::new(RefCell::new(Wire::new()))
    }
}
