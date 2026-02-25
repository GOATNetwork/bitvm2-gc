use serde::{Deserialize, Serialize};

/// Domain separator used to bind transcript hashing to this protocol instance.
pub const DEFAULT_DOMAIN_SEP: &[u8] = b"bitvm2-gc-argo-yao-v1";

/// Top-level commitment payload bound on-chain:
/// commit_root = H(domain_sep || session_id || vk_hash || root_yao || root_argo || public_input_hash).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitInputs {
    pub domain_sep: Vec<u8>,
    pub session_id: [u8; 32],
    pub vk_hash: [u8; 32],
    pub root_yao: [u8; 32],
    pub root_argo: [u8; 32],
    pub public_input_hash: [u8; 32],
}

impl CommitInputs {
    pub fn new(
        session_id: [u8; 32],
        vk_hash: [u8; 32],
        root_yao: [u8; 32],
        root_argo: [u8; 32],
        public_input_hash: [u8; 32],
    ) -> Self {
        Self {
            domain_sep: DEFAULT_DOMAIN_SEP.to_vec(),
            session_id,
            vk_hash,
            root_yao,
            root_argo,
            public_input_hash,
        }
    }
}

/// Merkle proof path element: sibling hash + whether sibling is on the left.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerklePathNode {
    pub sibling: [u8; 32],
    pub sibling_is_left: bool,
}

/// BLAKE3 helper, always 32-byte output.
pub fn h(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// Hash a leaf with explicit namespace:
/// leaf_hash = H("leaf" || leaf_data).
pub fn hash_leaf(leaf_data: &[u8]) -> [u8; 32] {
    let mut buf = b"leaf".to_vec();
    buf.extend_from_slice(leaf_data);
    h(&buf)
}

/// Hash an internal Merkle node with namespace:
/// node_hash = H("node" || left || right).
pub fn hash_node(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut buf = b"node".to_vec();
    buf.extend_from_slice(&left);
    buf.extend_from_slice(&right);
    h(&buf)
}

/// Build a binary Merkle root from leaf payloads.
/// If odd number of nodes at a level, duplicate the last node.
pub fn merkle_root_from_leaves(leaves: &[Vec<u8>]) -> [u8; 32] {
    if leaves.is_empty() {
        return h(b"empty-merkle");
    }
    let mut level: Vec<[u8; 32]> = leaves.iter().map(|leaf| hash_leaf(leaf)).collect();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            let last = *level.last().expect("non-empty level");
            level.push(last);
        }
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks_exact(2) {
            next.push(hash_node(pair[0], pair[1]));
        }
        level = next;
    }
    level[0]
}

/// Build Merkle root and proof for a selected leaf index.
pub fn merkle_root_and_proof(
    leaves: &[Vec<u8>],
    leaf_index: usize,
) -> Option<([u8; 32], Vec<MerklePathNode>)> {
    if leaves.is_empty() || leaf_index >= leaves.len() {
        return None;
    }
    let mut proof = Vec::<MerklePathNode>::new();
    let mut index = leaf_index;
    let mut level: Vec<[u8; 32]> = leaves.iter().map(|leaf| hash_leaf(leaf)).collect();

    while level.len() > 1 {
        if level.len() % 2 == 1 {
            let last = *level.last().expect("non-empty level");
            level.push(last);
        }

        let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
        let sibling_is_left = sibling_index < index;
        proof.push(MerklePathNode { sibling: level[sibling_index], sibling_is_left });

        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks_exact(2) {
            next.push(hash_node(pair[0], pair[1]));
        }
        index /= 2;
        level = next;
    }
    Some((level[0], proof))
}

/// Verify a Merkle inclusion proof against root.
pub fn verify_merkle_proof(root: [u8; 32], leaf_data: &[u8], proof: &[MerklePathNode]) -> bool {
    let mut acc = hash_leaf(leaf_data);
    for node in proof {
        acc = if node.sibling_is_left {
            hash_node(node.sibling, acc)
        } else {
            hash_node(acc, node.sibling)
        };
    }
    acc == root
}

/// Compute top-level commit root:
/// commit_root = H(domain_sep || session_id || vk_hash || root_yao || root_argo || public_input_hash).
pub fn compute_commit_root(input: &CommitInputs) -> [u8; 32] {
    let mut buf = Vec::with_capacity(
        input.domain_sep.len() + 32 + 32 + 32 + 32 + 32,
    );
    buf.extend_from_slice(&input.domain_sep);
    buf.extend_from_slice(&input.session_id);
    buf.extend_from_slice(&input.vk_hash);
    buf.extend_from_slice(&input.root_yao);
    buf.extend_from_slice(&input.root_argo);
    buf.extend_from_slice(&input.public_input_hash);
    h(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_root_and_inclusion() {
        let leaves = vec![
            b"yao:wire-0".to_vec(),
            b"yao:wire-1".to_vec(),
            b"argo:msg-0".to_vec(),
            b"argo:msg-1".to_vec(),
            b"cross:binding".to_vec(),
        ];
        let (root, proof) = merkle_root_and_proof(&leaves, 2).expect("proof");
        assert_eq!(root, merkle_root_from_leaves(&leaves));
        assert!(verify_merkle_proof(root, &leaves[2], &proof));
        assert!(!verify_merkle_proof(root, b"tampered", &proof));
    }

    #[test]
    fn test_commit_root_changes_when_any_field_changes() {
        let mut ci = CommitInputs::new([1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32]);
        let r0 = compute_commit_root(&ci);
        ci.root_argo = [9u8; 32];
        let r1 = compute_commit_root(&ci);
        assert_ne!(r0, r1);
    }
}
