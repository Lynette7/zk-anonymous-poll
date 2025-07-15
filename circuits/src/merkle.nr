use dep::std;

global MERKLE_TREE_DEPTH: u32 = 20;

// Return Merkle root from leaf and path
pub fn compute_merkle_root (
    leaf: Field,
    path: [Field; MERKLE_TREE_DEPTH],
    indices: [u1; MERKLE_TREE_DEPTH]
) -> Field {
    let mut current = leaf;

    for i in 0..MERKLE_TREE_DEPTH {
        let path_element = path[i];
        let is_right = indices[i];

        if is_right == 0 {
            //current is left child
            current = std::hash::pedersen_hash([current, path_element]);
        } else {
            //current is right child
            current = std::hash::pedersen_hash([path_element, current]);
        }
    }

    current
}

// Verify Merkle tree membership
pub fn verify_merkle_membership(
    leaf: Field,
    root: Field,
    path: [Field; MERKLE_TREE_DEPTH],
    indices: [u1; MERKLE_TREE_DEPTH]
) -> bool {
    let computed_root = compute_merkle_root(leaf, path, indices);
    computed_root == root
}
