use garbled_snark_verifier::bag::*;
use garbled_snark_verifier::core::gate::GateType;
use std::fs::File;
use std::io::{Result, Write};

pub fn write_vhdl(circuit: &Circuit, inputs: &[Wires], outputs: &[Wires], filename: &str) -> Result<()> {
    let mut f = File::create(filename)?;
    let total_wires = circuit.0.len();

    writeln!(f, "library IEEE;")?;
    writeln!(f, "use IEEE.STD_LOGIC_1164.ALL;\n")?;

    writeln!(f, "entity Circuit is")?;
    writeln!(f, "  Port (")?;

    // Write input port 
    for (i, group) in inputs.iter().enumerate() {
        writeln!(f, "    in{} : in std_logic_vector({} downto 0);", i, group.len() - 1)?;
    }

    // Write output port 
    for (i, group) in outputs.iter().enumerate() {
        let sep = if i == outputs.len() - 1 { "" } else { "," };
        writeln!(f, "    out{} : out std_logic_vector({} downto 0){}", i, group.len() - 1, sep)?;
    }

    writeln!(f, "  );")?;
    writeln!(f, "end Circuit;\n")?;

    writeln!(f, "architecture Behavioral of Circuit is")?;
    writeln!(f, "  signal w: std_logic_vector({} downto 0);", total_wires - 1)?;
    writeln!(f, "begin")?;

    // map input wire 
    let mut idx = 0;
    for (i, group) in inputs.iter().enumerate() {
        for j in 0..group.len() {
            writeln!(f, "  w{} <= in{}({});", idx, i, j)?;
            idx += 1;
        }
    }

    // Write gates
    for gate in &circuit.1 {
        let (a_idx, b_idx, c_idx) = (
            wire_id(&gate.wire_a),
            wire_id(&gate.wire_b),
            wire_id(&gate.wire_c),
        );
        match gate.gate_type {
            GateType::And => writeln!(f, "  w{} <= w{} and w{};", c_idx, a_idx, b_idx)?,
            GateType::Or => writeln!(f, "  w{} <= w{} or w{};", c_idx, a_idx, b_idx)?,
            GateType::Xor => writeln!(f, "  w{} <= w{} xor w{};", c_idx, a_idx, b_idx)?,
            GateType::Nand => writeln!(f, "  w{} <= not (w{} and w{});", c_idx, a_idx, b_idx)?,
            GateType::Nor => writeln!(f, "  w{} <= not (w{} or w{});", c_idx, a_idx, b_idx)?,
            GateType::Xnor => writeln!(f, "  w{} <= not (w{} xor w{});", c_idx, a_idx, b_idx)?,
            GateType::Not => writeln!(f, "  w{} <= not w{};", c_idx, a_idx)?,
            _ => writeln!(f, "-- unsupported gate {:?}", gate.gate_type)?,
        }
    }

    // Map output wire 
    for (i, group) in outputs.iter().enumerate() {
        for (j, wire) in group.iter().enumerate() {
            let wid = wire_id(wire);
            writeln!(f, "  out{}({}) <= w{};", i, j, wid)?;
        }
    }

    writeln!(f, "end Behavioral;")?;
    Ok(())
}

fn wire_id(w: &Wirex) -> usize {
    Rc::as_ptr(w) as usize
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::bristol::parser;

    #[test]
    pub fn test_write_vhdl() {
        let (circuit, inputs, outputs) = parser("src/bristol-examples/adder64.txt");
        write_vhdl(&circuit, &inputs, &outputs, "adder64.vhdl").unwrap();
    }
}