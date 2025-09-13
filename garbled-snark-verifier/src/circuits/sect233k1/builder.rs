//! Module provides a way to build binary circuits
use crate::bag::*;
use crate::circuits::sect233k1::curve_ckt::{CurvePoint, template_emit_point_add};
use crate::circuits::sect233k1::gf_ckt::GF_LEN;
use crate::core::gate::{Gate, GateTrait};
use std::collections::HashMap;
use std::time::Instant;

use crate::circuits::sect233k1::dv_ckt::WITNESS_BIT_LEN;
use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator, ParallelExtend,
    ParallelIterator,
};
use crate::core::lite_circuit::LiteCircuit;
use crate::core::wire::WireId;

/// Boolean Operation
#[derive(Debug, Clone)]
pub enum GateOperation {
    /// Basic Boolean Operations: AND, XOR
    Base(Operation<bool>),
    /// Custom Boolean Circuit: Point Add, Scalar Mul, etc
    Custom(CustomGateParams),
}

/// Operation type for compatibility
#[derive(Debug, Clone, Copy)]
pub enum Operation<T> {
    Add(u32, u32, u32), // XOR: output, input1, input2
    Mul(u32, u32, u32), // AND: output, input1, input2
    Or(u32, u32, u32),  // OR: output, input1, input2
    Const(u32, T),          // Constant: output, value
}

/// Custom Gate Type
#[derive(Debug, Clone, Copy)]
pub enum CustomGateType {
    PointAdd,
    // add more type here e.g fr_mul when needed for memory balance
}

/// Parameters that specify an instance of boolean circuit
///
/// An instance is uniquely identified by its type (which dictates circuit configuration),
/// what wires it is connected to (i.e. input wires to this circuit) and
/// a unique assignment for its internal wires. These are given by `gate_type`, `input_wire_labels`
/// and `internal_wire_label_start_index`
#[derive(Debug, Clone)]
pub struct CustomGateParams {
    /// type of custom gate: e.g Point Add
    gate_type: CustomGateType,
    /// wire indexes that the custom gate takes as input
    input_wire_index: Vec<u32>,
    /// offset for internal wire
    // We need to assign unique index to internal wire
    // `internal_wire_start_index` is the starting index
    // all internal wires and output wires are increments from this value
    internal_wire_start_index: u32,
}

/// Circuit Trait specifies how you represent the entire binary circuit.
/// It provides a way to prepare wire (input and constant gates),
/// assemble different type of gates (boolean or custom) and inspect them.
///
/// How wire  are assigned and how the gates are represented in memory
/// depends upon the implementation.
pub trait CircuitTrait {
    /// get fresh wire index
    fn fresh_one(&mut self) -> u32;

    /// get fresh wire indexes
    fn fresh<const N: usize>(&mut self) -> [u32; N];

    /// get wire index for constant zero wire
    fn zero(&mut self) -> u32;

    /// get wire index for constant one wire
    fn one(&mut self) -> u32;

    /// XOR two input wires and return wire index of output
    fn xor_wire(&mut self, x: u32, y: u32) -> u32;

    /// OR two input wires and return wire index of output
    fn or_wire(&mut self, x: u32, y: u32) -> u32;

    // AND two input wires and return wire index of output
    fn and_wire(&mut self, x: u32, y: u32) -> u32;

    /// push an instance of custom gate. `params` specifies the current instance of Custom Gate.
    /// `new_wire_idx` represents the new next wire index
    fn push_custom_gate(&mut self, params: CustomGateParams, new_wire_idx: u32);

    /// get all gates
    fn get_gates(&self) -> &Vec<GateOperation>;

    /// next wire index
    fn next_wire(&self) -> u32;

    /// initialize circuit configuration for custom gate
    /// `Template` specifies circuit configuration.
    // This is known only by executing the operation represented by circuit type.
    // For example to determine circuit configuration of a Point Addition,
    // you execute circuit compiler for that corresponding module
    fn init_circuit_config_for_custom_gate(&mut self, templ_type: CustomGateType) -> &Template;

    /// get template (circuit configuration) of `templ_type` if it exists
    fn get_template(&self, templ_type: CustomGateType) -> Option<&Template>;
}

/// Adapter that wraps the original Circuit to implement the new Circuit trait
#[derive(Debug)]
pub struct CircuitAdapter {
    // // Original circuit from the first implementation
    // inner_circuit: Circuit,
    // // Wire mapping: usize -> Wire
    // wire_map: HashMap<usize, Wire>,
    // Next wire index
    next_wire: u32,
    // Constant wire index
    zero: Option<u32>,
    one: Option<u32>,
    // Gates in the new format
    gates: Vec<GateOperation>,
    // Templates for custom gates
    templates: Templates,
}

impl Default for CircuitAdapter {
    fn default() -> Self {
        // let mut wire_map = HashMap::new();
        // wire_map.insert(0, new_wirex()); // constant 0
        // wire_map.insert(1, new_wirex()); // constant 1

        CircuitAdapter {
            // inner_circuit: Circuit::empty(),
            // wire_map,
            next_wire: 2, // Start from 2, reserving 0 and 1 for constants
            zero: Some(0),
            one: Some(1),
            gates: vec![],
            templates: Templates::default(),
        }
    }
}

#[derive(Default, Debug)]
pub struct Templates {
    pub ptadd_template: Option<Template>,
}

impl CircuitAdapter {
    pub(crate) fn build(&self, witness: [bool; WITNESS_BIT_LEN]) -> LiteCircuit {
        let n_wires = self.next_wire;
        println!("wires: {n_wires}");

        let start = Instant::now();

        let mut wires = Vec::with_capacity(n_wires as usize);
        for i in 0..n_wires {
            if i.is_multiple_of(10_000_000) {
                println!("wires: {} M", i / 1_000_000);
            }
            wires.push(Wire::new());
        }
        println!("init wires took:{:?}", start.elapsed());

        // Set constant and witness wire values.
        // This is an efficient way to initialize the first few wires.
        let all_bits_iter = [false, true].iter().chain(witness.iter());
        wires.iter_mut().zip(all_bits_iter).for_each(|(wire, bit)| {
            wire.set(*bit);
        });

        let start = Instant::now();
        // To reduce peak memory usage, we avoid creating the large intermediate `basic_ops` vector.
        // Instead, we iterate through the top-level gates, unroll them one by one,
        // and immediately convert the resulting basic operations into `Gate` objects.
        // This trades the top-level parallelism of the unrolling step for lower memory consumption,
        // while retaining internal parallelism within `unroll_custom_gate`.
        let gates: Vec<Gate<WireId>> = self
            .gates
            .iter()
            .enumerate()
            .flat_map(|(i, g)| {
                // Unroll the current gate `g` into a temporary list of basic operations.
                // This temporary list is much smaller than the full `basic_ops` vector would be.
                let ops_for_this_gate = match g {
                    GateOperation::Base(op) => vec![*op],
                    GateOperation::Custom(params) => {
                        let templ = self.get_template(params.gate_type).unwrap_or_else(|| {
                            panic!(
                                "Template for custom gate {:?} not initialized",
                                params.gate_type
                            )
                        });
                        templ.unroll_custom_gate(
                            self.zero,
                            self.one,
                            params.internal_wire_start_index,
                            &params.input_wire_index,
                        )
                    }
                };

                // Immediately convert these basic operations to `Gate` objects.
                // This consumes `ops_for_this_gate`, and its memory is freed after this block.
                // This creates an iterator that `flat_map` will process.
                ops_for_this_gate.into_iter()
            })
            .enumerate()
            .filter_map(|(i, op)| {
                if i.is_multiple_of(10_000_000) {
                    println!("processing II {} M", i / 1_000_000);
                }
                match op {
                    Operation::Add(d, x, y) => {
                        Some(Gate::xor(x, y, d))
                    }
                    Operation::Mul(d, x, y) => {
                        Some(Gate::and(x, y, d))
                    }
                    Operation::Or(d, x, y) => {
                        Some(Gate::or(x, y, d))
                    }
                    Operation::Const(_, _) => None,
                }
            })
            .collect();
        println!("gates to circuit took:{:?}", start.elapsed());

        // The circuit output is assumed to be the last wire.
        // Using `expect` for a clearer error message if `wires` is empty.
        LiteCircuit::new(vec![(n_wires - 1) as WireId], gates, wires)
    }
}

impl CircuitTrait for CircuitAdapter {
    fn fresh_one(&mut self) -> u32 {
        let index = self.next_wire;
        self.next_wire += 1;

        index
    }

    fn fresh<const N: usize>(&mut self) -> [u32; N] {
        let mut out = [0; N];
        for slot in &mut out {
            *slot = self.fresh_one();
        }

        out
    }

    fn zero(&mut self) -> u32 {
        if let Some(z) = self.zero {
            return z;
        }
        let w = self.fresh_one();
        self.zero = Some(w);

        w
    }

    fn one(&mut self) -> u32 {
        if let Some(o) = self.one {
            return o;
        }
        let w = self.fresh_one();
        self.one = Some(w);

        w
    }

    fn xor_wire(&mut self, x: u32, y: u32) -> u32 {
        if x == y {
            return self.zero();
        }
        if x == self.zero() {
            return y;
        }
        if y == self.zero() {
            return x;
        }
        let output = self.fresh_one();
        self.gates.push(GateOperation::Base(Operation::Add(output as u32, x as u32, y as u32)));

        output
    }

    fn or_wire(&mut self, x: u32, y: u32) -> u32 {
        if x == y {
            return x;
        }

        let one = self.one();
        if x == one || y == one {
            return one;
        }

        let zero = self.zero();
        if x == zero {
            return y;
        }
        if y == zero {
            return x;
        }

        let output = self.fresh_one();
        self.gates.push(GateOperation::Base(Operation::Or(output as u32, x as u32, y as u32)));

        output
    }

    fn and_wire(&mut self, x: u32, y: u32) -> u32 {
        if x == y {
            return x;
        }

        let zero = self.zero();
        if x == zero || y == zero {
            return zero;
        }

        let one = self.one();
        if x == one {
            return y;
        }
        if y == one {
            return x;
        }

        let output = self.fresh_one();
        self.gates.push(GateOperation::Base(Operation::Mul(output as u32, x as u32, y as u32)));

        output
    }

    fn push_custom_gate(&mut self, params: CustomGateParams, new_wire_idx: u32) {
        self.gates.push(GateOperation::Custom(params));
        self.next_wire = new_wire_idx;
    }

    fn get_gates(&self) -> &Vec<GateOperation> {
        &self.gates
    }

    fn next_wire(&self) -> u32 {
        self.next_wire
    }

    fn init_circuit_config_for_custom_gate(&mut self, templ_type: CustomGateType) -> &Template {
        match templ_type {
            CustomGateType::PointAdd => {
                if self.templates.ptadd_template.is_none() {
                    let template = template_emit_point_add();
                    self.templates.ptadd_template = Some(template);
                }
            }
        }
        self.templates.ptadd_template.as_ref().unwrap()
    }

    fn get_template(&self, templ_type: CustomGateType) -> Option<&Template> {
        match templ_type {
            CustomGateType::PointAdd => self.templates.ptadd_template.as_ref(),
        }
    }
}

// Helper functions to match the original interface
pub fn xor_three<T: CircuitTrait>(b: &mut T, x: u32, y: u32, z: u32) -> u32 {
    let x_xor_y = b.xor_wire(x, y);
    b.xor_wire(x_xor_y, z)
}

pub fn xor_vec<T: CircuitTrait>(bld: &mut T, a: &[u32], b: &[u32]) -> Vec<u32> {
    let len = a.len().max(b.len());
    (0..len)
        .map(|i| match (a.get(i), b.get(i)) {
            (Some(&x), Some(&y)) => bld.xor_wire(x, y),
            (Some(&x), None) => x,
            (None, Some(&y)) => y,
            _ => unreachable!(),
        })
        .collect()
}

pub fn xor_many<T: CircuitTrait>(bld: &mut T, items: impl IntoIterator<Item=u32>) -> u32 {
    let mut it = items.into_iter();
    let first = match it.next() {
        Some(w) => w,
        None => return bld.zero(),
    };
    it.fold(first, |acc, w| bld.xor_wire(acc, w))
}

/// Custom Gate Configuration
///
/// Configuration of a circuit is defined by its input wires, gates and output wires.
/// We include `start_wire_idx` and `end_wire_idx` so that a different instance of
/// a binary circuit of a configuration can be instantiated. These fields help uniquely
/// label internal wires, while the other fields specify how these wire are connected.
///
/// The `stats` field is a metric to obtain gate counts for benchmarks
#[derive(Default, Clone, Debug)]
pub struct Template {
    /// input wire indexes to this circuit
    pub input_wires: Vec<u32>,
    /// logic gates in this circuit
    pub gates: Vec<GateOperation>,
    /// output wire indexes from this circuit
    pub output_wires: Vec<u32>,
    /// wire index corresponding to constant value zero
    pub const_wire_zero: u32,
    // wire index corresponding to constant value one
    pub const_wire_one: u32,

    /// starting wire index of internal wires
    pub start_wire_idx: u32,
    /// final wire index of internal wires plus one
    // "plus one" here because end_wire_idx saves value of CktBuilder::next_wire
    pub end_wire_idx: u32,

    // count of AND, XOR, OR gates in this circuit
    pub stats: (usize, usize, usize),
}

impl Template {
    /// Generate binary circuit for point addition using cached configuration 'template' for this circuit.
    /// Input is the same as it would normally be for point addition, which is two CurvePoints
    pub fn emit_point_add_custom<T: CircuitTrait>(
        bld: &mut T,
        p1: &CurvePoint,
        p2: &CurvePoint,
    ) -> CurvePoint {
        // serialize wire indexes in the same order accepted by the circuit configuration
        let mut input_wires = vec![];
        input_wires.extend_from_slice(&p1.x);
        input_wires.extend_from_slice(&p1.s);
        input_wires.extend_from_slice(&p1.z);
        input_wires.extend_from_slice(&p1.t);

        input_wires.extend_from_slice(&p2.x);
        input_wires.extend_from_slice(&p2.s);
        input_wires.extend_from_slice(&p2.z);
        input_wires.extend_from_slice(&p2.t);

        // Generate an instance of this custom gate using circuit configuration for the template
        // and return output wire indexes
        let output_wires = Self::emit_custom(bld, input_wires, CustomGateType::PointAdd);

        // Deserialize wire indexes into expected data structure
        CurvePoint {
            x: output_wires[0..GF_LEN].try_into().unwrap(),
            s: output_wires[GF_LEN..GF_LEN * 2].try_into().unwrap(),
            z: output_wires[GF_LEN * 2..GF_LEN * 3].try_into().unwrap(),
            t: output_wires[GF_LEN * 3..GF_LEN * 4].try_into().unwrap(),
        }
    }

    /// Instantiate binary circuit of known configuration.
    /// Configuration is known by `gate_type`. Each instance of the circuit has its own set of inputs,
    /// which is defined by `input_wires`
    fn emit_custom<T: CircuitTrait>(
        bld: &mut T,
        input_wires: Vec<u32>,
        gate_type: CustomGateType,
    ) -> Vec<u32> {
        // Build Configuration if it doesn't already exist
        if bld.get_template(gate_type).is_none() {
            bld.init_circuit_config_for_custom_gate(gate_type);
        }
        let tmpl = bld.get_template(gate_type).unwrap();

        assert_eq!(tmpl.input_wires.len(), input_wires.len());

        let internal_wire_starting_index = bld.next_wire() - tmpl.start_wire_idx;

        // output wires are also labelled as any internal wire i.e. assigned a unique value
        let ref_output_set: Vec<u32> =
            tmpl.output_wires.iter().map(|x| x + internal_wire_starting_index).collect();

        let next_wire = bld.next_wire();
        bld.push_custom_gate(
            CustomGateParams {
                gate_type,
                input_wire_index: input_wires,
                internal_wire_start_index: internal_wire_starting_index,
            },
            // new wire index is obtained by adding the next wire index by
            // the total number of internal wires defined within this configuration.
            // like any batch wire assignment
            next_wire + (tmpl.end_wire_idx - tmpl.start_wire_idx),
        );

        ref_output_set
    }

    /// Convert custom gate to basic gates
    pub fn unroll_custom_gate(
        &self,
        zero: Option<u32>,
        one: Option<u32>,
        internal_wire_start_offset: u32,
        input_wires: &[u32],
    ) -> Vec<Operation<bool>> {
        assert_eq!(self.input_wires.len(), input_wires.len());

        // wire_map maps template wire indexes to instance specific wire indexes
        let mut wire_map: HashMap<u32, u32> =
            self.input_wires.par_iter().copied().zip(input_wires.to_owned()).collect();

        // iterate through internal wire indexes of the template
        // and offset by a value `internal_wire_start_offset` specific to this instance to generate new wire indexes
        wire_map.par_extend(
            (self.start_wire_idx..self.end_wire_idx)
                .into_par_iter()
                .map(|old_idx| (old_idx, old_idx + internal_wire_start_offset)),
        );
        if let Some(zero) = zero {
            wire_map.insert(self.const_wire_zero, zero);
        }
        if let Some(one) = one {
            wire_map.insert(self.const_wire_one, one);
        }

        // Iterate through each of the gates and map wire indexes from the ones in template
        // to wire indexes unique to this instant
        self.gates
            .par_iter()
            .map(|h| match h {
                GateOperation::Base(g) => {
                    let ret = match *g {
                        Operation::Add(d, x, y) => {
                            let nd = wire_map.get(&d).unwrap();
                            let nx = wire_map.get(&x).unwrap();
                            let ny = wire_map.get(&y).unwrap();
                            Operation::Add(*nd, *nx, *ny)
                        }
                        Operation::Mul(d, x, y) => {
                            let nd = wire_map.get(&d).unwrap();
                            let nx = wire_map.get(&x).unwrap();
                            let ny = wire_map.get(&y).unwrap();
                            Operation::Mul(*nd, *nx, *ny)
                        }
                        Operation::Or(d, x, y) => {
                            let nd = wire_map.get(&d).unwrap();
                            let nx = wire_map.get(&x).unwrap();
                            let ny = wire_map.get(&y).unwrap();
                            Operation::Or(*nd, *nx, *ny)
                        }
                        Operation::Const(d, v) => {
                            let nd = wire_map.get(&d).unwrap();
                            Operation::Const(*nd, v)
                        }
                    };
                    vec![ret]
                }
                GateOperation::Custom(g) => self.unroll_custom_gate(
                    zero,
                    one,
                    g.internal_wire_start_index,
                    &g.input_wire_index,
                ),
            })
            .flatten()
            .collect()
    }
}

impl CircuitAdapter {
    /// show gate counts in the current CircuitAdapter
    pub fn show_gate_counts(&mut self) {
        let mut and_gates_count = 0;
        let mut xor_gates_count = 0;
        let mut or_gates_count = 0;
        let mut custom_gates_count = 0;

        let (tmp_mul, tmp_add, tmp_or) = {
            if let Some(tmpl) = self.get_template(CustomGateType::PointAdd) {
                (Some(tmpl.stats.0), Some(tmpl.stats.1), Some(tmpl.stats.2))
            } else {
                // if custom gate is not initialized return 0
                (None, None, None)
            }
        };

        for h in self.get_gates() {
            match h {
                GateOperation::Base(g) => match g {
                    Operation::Add(_, _, _) => {
                        xor_gates_count += 1;
                    }
                    Operation::Mul(_, _, _) => {
                        and_gates_count += 1;
                    }
                    Operation::Or(_, _, _) => {
                        or_gates_count += 1;
                    }
                    _ => unreachable!(),
                },
                GateOperation::Custom(_) => {
                    custom_gates_count += 1;
                    if let Some(tmp_add) = tmp_add {
                        xor_gates_count += tmp_add;
                    }
                    if let Some(tmp_mul) = tmp_mul {
                        and_gates_count += tmp_mul;
                    }
                    if let Some(tmp_or) = tmp_or {
                        or_gates_count += tmp_or;
                    }
                }
            }
        }
        println!("and_gates_count {}", and_gates_count);
        println!("xor_gates_count {}", xor_gates_count);
        println!("or_gates_count {}", or_gates_count);
        println!("custom_gates_count {}", custom_gates_count);
        println!("total_gates_count {}", self.get_gates().len());
    }

    /// Evaluate a binary circuit given `witness` as input wire values.
    /// Assumes that these `witness` values correspond to wire labels from 2 to 2+num_input_wires.
    /// as the first two wire labels are always constant wire labels 0 and 1.
    pub fn eval_gates(&self, witness: &[bool]) -> Vec<bool> {
        let n_wires = self.next_wire;
        let mut w = vec![None; n_wires as usize];
        let gates = &self.gates;
        let zero_gate = self.zero;
        let one_gate = self.one;
        assert_eq!(zero_gate, Some(0));
        w[zero_gate.unwrap() as usize] = Some(false);
        assert_eq!(one_gate, Some(1));
        w[one_gate.unwrap() as usize] = Some(true);

        const WIRE_OFFSET: usize = 2; // due to 0 and 1 at the first two index
        for (id, &bit) in witness.iter().enumerate() {
            w[WIRE_OFFSET + id] = Some(bit);
        }

        for h in gates {
            match h {
                GateOperation::Base(g) => {
                    match *g {
                        Operation::Add(d, x, y) => w[d as usize] = Some(w[x as usize].unwrap() ^ w[y as usize].unwrap()),
                        Operation::Mul(d, x, y) => w[d as usize] = Some(w[x as usize].unwrap() & w[y as usize].unwrap()),
                        Operation::Or(d, x, y) => w[d as usize] = Some(w[x as usize].unwrap() | w[y as usize].unwrap()),
                        // Operation::Const(d, v) => w[d] = Some(v),
                        _ => unreachable!(), // no other variants used
                    }
                }
                GateOperation::Custom(params) => {
                    let custom_gate_template = match params.gate_type {
                        CustomGateType::PointAdd => self.templates.ptadd_template.as_ref().unwrap(),
                    };
                    let gates = custom_gate_template.unroll_custom_gate(
                        zero_gate,
                        one_gate,
                        params.internal_wire_start_index,
                        &params.input_wire_index,
                    );
                    for g in gates {
                        match g {
                            Operation::Add(d, x, y) => w[d as usize] = Some(w[x as usize].unwrap() ^ w[y as usize].unwrap()),
                            Operation::Mul(d, x, y) => w[d as usize] = Some(w[x as usize].unwrap() & w[y as usize].unwrap()),
                            Operation::Or(d, x, y) => w[d as usize] = Some(w[x as usize].unwrap() | w[y as usize].unwrap()),
                            // Operation::Const(d, v) => w[d] = Some(v),
                            _ => unreachable!(), // no other variants used
                        }
                    }
                }
            }
        }

        w.iter().map(|x| x.unwrap()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_operations() {
        let mut circuit = CircuitAdapter::default();

        // Test fresh wire creation
        let w1 = circuit.fresh_one();
        let w2 = circuit.fresh_one();
        assert_ne!(w1, w2);

        // Test constant wires
        let zero = circuit.zero();
        let one = circuit.one();
        assert_eq!(zero, 0);
        assert_eq!(one, 1);

        // Test logical operations
        let and_result = circuit.and_wire(w1, w2);
        let xor_result = circuit.xor_wire(w1, w2);
        let or_result = circuit.or_wire(w1, w2);

        // Verify that operations create unique outputs
        assert_ne!(and_result, xor_result);
        assert_ne!(and_result, or_result);
        assert_ne!(xor_result, or_result);

        // Verify gates were created
        assert!(!circuit.get_gates().is_empty());
    }

    #[test]
    fn test_batch_operations() {
        let mut circuit = CircuitAdapter::default();

        // Test batch wire creation
        let wires: [u32; 4] = circuit.fresh();
        for i in 0..4 {
            for j in i + 1..4 {
                assert_ne!(wires[i], wires[j]);
            }
        }

        // Test XOR of multiple wires
        let result = xor_many(&mut circuit, wires);
        assert_ne!(result, 0); // Should not be zero wire

        // Test XOR of vectors
        let a = &wires[0..2];
        let b = &wires[2..4];
        let vec_result = xor_vec(&mut circuit, a, b);
        assert_eq!(vec_result.len(), 2);
    }
}
