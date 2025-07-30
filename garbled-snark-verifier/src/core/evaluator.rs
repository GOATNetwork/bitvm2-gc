use std::fs;
use crate::bag::{new_wirex, Circuit, Gate, Wires};
use crate::core::gate::GateType;
use crate::core::s::S;

/// Parses a circuit from a Bristol format file.
pub fn parser(filename: &str) -> (Circuit, Vec<Wires>, Vec<Wires>) {
    let data = fs::read_to_string(filename).expect("error");
    let mut lines = data.lines();

    let mut words = lines.next().unwrap().split_whitespace();
    let nog: usize = words.next().unwrap().parse().unwrap();
    let now: usize = words.next().unwrap().parse().unwrap();
    let mut wires = Vec::new();
    for _ in 0..now {
        wires.push(new_wirex());
    }

    let mut input_sizes = Vec::<usize>::new();
    let mut words = lines.next().unwrap().split_whitespace();
    for _ in 0..words.next().unwrap().parse().unwrap() {
        let x: usize = words.next().unwrap().parse().unwrap();
        input_sizes.push(x);
    }

    let mut output_sizes = Vec::<usize>::new();
    let mut words = lines.next().unwrap().split_whitespace();
    for _ in 0..words.next().unwrap().parse().unwrap() {
        let x: usize = words.next().unwrap().parse().unwrap();
        output_sizes.push(x);
    }

    let mut i = 0;
    let mut gates = Vec::new();
    while i < nog {
        let line = lines.next().unwrap();
        if line.is_empty() {
            continue;
        }
        let mut words = line.split_whitespace();
        let gate_id: usize = words.next().unwrap().parse().unwrap();
        let number_of_inputs: usize = words.next().unwrap().parse().unwrap();
        let number_of_outputs: usize = words.next().unwrap().parse().unwrap();
        let mut input_wires: Vec<usize> = Vec::new();
        for _ in 0..number_of_inputs {
            input_wires.push(words.next().unwrap().parse().unwrap());
        }
        let mut output_wires: Vec<usize> = Vec::new();
        for _ in 0..number_of_outputs {
            output_wires.push(words.next().unwrap().parse().unwrap());
        }
        let gate_type_str = words.next().unwrap().to_lowercase();
        let gate_type = match gate_type_str.as_str() {
            "and" => GateType::And,
            "or" => GateType::Or,
            "xor" => GateType::Xor,
            "nor" => GateType::Nor,
            "nand" => GateType::Nand,
            "inv" | "not" => GateType::Not,
            "xnor" => GateType::Xnor,
            "nimp" => GateType::Nimp,
            "ncimp" => GateType::Ncimp,
            "cimp" => GateType::Cimp,
            "imp" => GateType::Imp,
            _ => panic!("Unknown gate type: {}", gate_type_str),
        };
        let gate = Gate::new_with_gid(
            wires[input_wires[0]].clone(),
            if number_of_inputs == 1 {
                wires[input_wires[0]].clone()
            } else {
                wires[input_wires[1]].clone()
            },
            wires[output_wires[0]].clone(),
            gate_type,
            gate_id as u32,
        );
        gates.push(gate);
        i += 1;
    }
    let c = Circuit::new(wires.clone(), gates);

    let mut inputs = Vec::new();
    let wires_copy = wires.clone();
    let mut wires_iter = wires_copy.iter();
    for input_size in input_sizes {
        let mut input = Vec::new();
        for _ in 0..input_size {
            input.push(wires_iter.next().unwrap().clone());
        }
        inputs.push(input);
    }

    let mut outputs = Vec::new();
    let mut wires_reversed = wires.clone();
    wires_reversed.reverse();
    let mut wires_iter = wires_reversed.iter();
    for output_size in output_sizes.iter().rev() {
        let mut output = Vec::new();
        for _ in 0..*output_size {
            output.push(wires_iter.next().unwrap().clone());
        }
        output.reverse();
        outputs.push(output);
    }
    outputs.reverse();

    (c, inputs, outputs)
}

pub fn evaluator(
    circuit_file: &str,
    garblings: &[Option<S>],
    input_tuples: &[Vec<(S, bool)>],
    expected_output_label: S,
) {
    let (mut circuit, input_wires, output_wires) = parser(circuit_file);

    for (i, input_wires) in input_wires.iter().enumerate() {
        for (j, wire) in input_wires.iter().enumerate() {
            let (label, bit) = input_tuples[i][j];
            wire.borrow_mut().set_label(label);
            wire.borrow_mut().set(bit);
        }
    }

    for gate in &mut circuit.1 {
        gate.evaluate();
    }

    let computed_garblings = circuit.garbled_gates();
    assert_eq!(computed_garblings, garblings);

    let computed_output_label = circuit.garbled_evaluate(garblings);
    assert_eq!(computed_output_label, expected_output_label);
}

#[cfg(test)]
mod tests {
    use crate::bag::new_wirex;
    use crate::circuits::basic::selector;
    use super::*;

    #[test]
    fn test_selector_circuit_evaluator() {
        let mut wire_a = new_wirex();
        wire_a.borrow_mut().set(false);
        let mut wire_b = new_wirex();
        wire_b.borrow_mut().set(true);
        let mut wire_c = new_wirex();
        wire_c.borrow_mut().set(false);

        let mut circuit = selector(wire_a.clone(), wire_b.clone(), wire_c.clone());

        for gate in &mut circuit.1 {
            gate.evaluate();
        }
        let garblings = circuit.garbled_gates();
        let expected_output_label = circuit.garbled_evaluate(&garblings);

        let input_tuples = vec![vec![(wire_a.borrow().get_label(), wire_a.borrow().get_value())],
                                vec![(wire_b.borrow().get_label(), wire_b.borrow().get_value())],
                                vec![(wire_c.borrow().get_label(), wire_c.borrow().get_value())]];


        evaluator(
            "bristol-examples/selector.txt",
            &garblings,
            &input_tuples,
            expected_output_label
        );
    }
}