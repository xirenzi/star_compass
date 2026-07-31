//! Merkle 树 - 消息完整性锚点

use sha2::{Digest, Sha256};

/// 叶子节点：msg_id(8) || offset(4) || payload(107) 的 SHA-256
#[derive(Clone)]
pub struct LeafNode([u8; 32]);

impl LeafNode {
    pub fn new(msg_id: u64, offset: u32, payload: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(&msg_id.to_le_bytes());
        hasher.update(&offset.to_le_bytes());
        hasher.update(payload);
        let result = hasher.finalize();
        let mut node = [0u8; 32];
        node.copy_from_slice(&result);
        LeafNode(node)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&[0x00]);
        hasher.update(&self.0);
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }
}

fn combine(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&[0x01]);
    hasher.update(left);
    hasher.update(right);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Merkle 树（层状数组存储）
pub struct MerkleTree {
    root: [u8; 32],
    /// levels[i] = 该层节点的 hash 列表，i=0 为叶子层
    levels: Vec<Vec<[u8; 32]>>,
}

impl MerkleTree {
    pub fn build(data: Vec<(u64, u32, Vec<u8>)>) -> Self {
        if data.is_empty() {
            return MerkleTree { root: [0u8; 32], levels: vec![] };
        }

        // 叶子层 hash
        let mut leaves: Vec<[u8; 32]> = data
            .iter()
            .map(|(msg_id, offset, payload)| LeafNode::new(*msg_id, *offset, payload).hash())
            .collect();

        // padding 到 2 的幂
        let mut level0_width = 1;
        while level0_width < leaves.len() {
            level0_width <<= 1;
        }
        while leaves.len() < level0_width {
            leaves.push([0u8; 32]);
        }

        let mut levels: Vec<Vec<[u8; 32]>> = vec![leaves];

        // 自底向上构建
        while levels.last().unwrap().len() > 1 {
            let parent = levels.last().unwrap();
            let new_level: Vec<[u8; 32]> = parent
                .chunks(2)
                .map(|pair| combine(&pair[0], &pair[1.min(pair.len() - 1)]))
                .collect();
            levels.push(new_level);
        }

        let root = *levels.last().unwrap().first().unwrap();
        MerkleTree { root, levels }
    }

    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// 生成证明：leaf_index 对应的 (is_left, sibling_hash) 列表
    pub fn proof(&self, leaf_index: usize) -> Option<MerkleProof> {
        if self.levels.is_empty() || leaf_index >= self.levels[0].len() {
            return None;
        }

        let mut path = Vec::new();
        let mut idx = leaf_index;

        for level in 0..self.levels.len() - 1 {
            let sibling = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            let is_left = idx % 2 == 0;
            let sibling_hash = if sibling < self.levels[level].len() {
                self.levels[level][sibling]
            } else {
                [0u8; 32]
            };
            path.push((is_left, sibling_hash));
            idx /= 2;
        }

        Some(MerkleProof { leaf_index, path })
    }

    pub fn verify(&self, leaf: &LeafNode, proof: &MerkleProof) -> bool {
        let mut current = leaf.hash();

        for (is_left, sibling) in &proof.path {
            current = if *is_left {
                combine(&current, sibling)
            } else {
                combine(sibling, &current)
            };
        }

        current == self.root
    }
}

#[derive(Debug, Clone)]
pub struct MerkleProof {
    pub leaf_index: usize,
    /// (is_left_sibling, sibling_hash)
    pub path: Vec<(bool, [u8; 32])>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_tree(leaf_count: usize) -> (MerkleTree, Vec<LeafNode>) {
        let data: Vec<_> = (0..leaf_count)
            .map(|i| (i as u64, 0, vec![i as u8; 107]))
            .collect();
        let leaves: Vec<_> = data
            .iter()
            .map(|(id, off, pay)| LeafNode::new(*id, *off, pay))
            .collect();
        let tree = MerkleTree::build(data);
        (tree, leaves)
    }

    #[test]
    fn test_merkle_build() {
        let (tree, leaves) = build_tree(3);
        assert_ne!(tree.root(), [0u8; 32]);

        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.proof(i).unwrap();
            assert!(tree.verify(leaf, &proof), "leaf {} should verify", i);
        }
    }

    #[test]
    fn test_merkle_wrong_leaf() {
        let (tree, leaves) = build_tree(2);
        let wrong = LeafNode::new(99, 0, &vec![0xFF; 107]);
        let proof = tree.proof(0).unwrap();
        assert!(!tree.verify(&wrong, &proof), "wrong leaf should not verify");
        assert!(tree.verify(&leaves[0], &proof), "correct leaf should verify");
    }

    #[test]
    fn test_merkle_single() {
        let (tree, leaves) = build_tree(1);
        let proof = tree.proof(0).unwrap();
        assert!(tree.verify(&leaves[0], &proof), "single leaf should verify");
    }

    #[test]
    fn test_merkle_padding() {
        // padding 到 4 leaves
        let (tree, leaves) = build_tree(3);
        assert_eq!(tree.levels[0].len(), 4);
        let proof = tree.proof(2).unwrap();
        assert!(tree.verify(&leaves[2], &proof), "padded leaf should verify");
    }
}
