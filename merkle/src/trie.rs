use std::cell::RefCell;
use std::convert::TryInto;
use std::rc::Rc;

use alloy_rlp::EMPTY_STRING_CODE;
use types::{MerkleProof, MerkleProofNode, Nibbles, H256};

use crate::node::{empty_children, BranchNode, Node};

pub trait IterativeTrie {
    fn insert(&mut self, key: Vec<u8>, value: Vec<u8>);
    fn merkle_proof(&self, key: Vec<u8>) -> MerkleProof;
}

#[derive(Debug, Default)]
pub struct PatriciaTrie {
    root: Node,
}

#[derive(Clone, Debug)]
enum TraceStatus {
    Start,
    Doing,
    Child(u8),
    End,
}

#[derive(Clone, Debug)]
struct TraceNode {
    node: Node,
    status: TraceStatus,
}

impl TraceNode {
    fn advance(&mut self) {
        self.status = match &self.status {
            TraceStatus::Start => TraceStatus::Doing,
            TraceStatus::Doing => match self.node {
                Node::Branch(_) => TraceStatus::Child(0),
                _ => TraceStatus::End,
            },
            TraceStatus::Child(i) if *i < 15 => TraceStatus::Child(i + 1),
            _ => TraceStatus::End,
        }
    }
}

impl From<Node> for TraceNode {
    fn from(node: Node) -> TraceNode {
        TraceNode {
            node,
            status: TraceStatus::Start,
        }
    }
}

pub struct TrieIterator {
    nibble: Nibbles,
    nodes: Vec<TraceNode>,
}

impl Iterator for TrieIterator {
    type Item = (Vec<u8>, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let mut now = self.nodes.last().cloned();
            if let Some(ref mut now) = now {
                self.nodes.last_mut().unwrap().advance();

                match (now.status.clone(), &now.node) {
                    (TraceStatus::End, node) => {
                        match *node {
                            Node::Leaf(ref leaf) => {
                                let cur_len = self.nibble.len();
                                self.nibble.truncate(cur_len - leaf.borrow().key.len());
                            }

                            Node::Extension(ref ext) => {
                                let cur_len = self.nibble.len();
                                self.nibble.truncate(cur_len - ext.borrow().prefix.len());
                            }

                            Node::Branch(_) => {
                                self.nibble.pop();
                            }
                            _ => {}
                        }
                        self.nodes.pop();
                    }

                    (TraceStatus::Doing, Node::Extension(ref ext)) => {
                        self.nibble.extend(&ext.borrow().prefix);
                        self.nodes.push((ext.borrow().node.clone()).into());
                    }

                    (TraceStatus::Doing, Node::Leaf(ref leaf)) => {
                        self.nibble.extend(&leaf.borrow().key);
                        return Some((self.nibble.encode_raw().0, leaf.borrow().value.clone()));
                    }

                    (TraceStatus::Doing, Node::Branch(ref branch)) => {
                        let value = branch.borrow().value.clone();
                        if let Some(data) = value {
                            return Some((self.nibble.encode_raw().0, data));
                        } else {
                            continue;
                        }
                    }

                    (TraceStatus::Child(i), Node::Branch(ref branch)) => {
                        if i == 0 {
                            self.nibble.push(0);
                        } else {
                            self.nibble.pop();
                            self.nibble.push(i);
                        }
                        self.nodes
                            .push((branch.borrow().children[i as usize].clone()).into());
                    }

                    (_, Node::Empty) => {
                        self.nodes.pop();
                    }
                    _ => {}
                }
            } else {
                return None;
            }
        }
    }
}

impl PatriciaTrie {
    pub fn iter(&self) -> TrieIterator {
        let nodes = vec![self.root.clone().into()];
        TrieIterator {
            nibble: Nibbles::from_raw(vec![], false),
            nodes,
        }
    }
    pub fn new() -> Self {
        Default::default()
    }
}

impl PatriciaTrie {
    pub fn root_node(&self) -> Node {
        self.root.clone()
    }

    fn insert_at_iterative(n: Node, partial_key: Nibbles, value: Vec<u8>) -> Node {
        let mut queue = vec![n];
        let mut partial = Clone::clone(&partial_key);

        // Part 1: Find place to insert, or replace value.
        // Meanwhile, nodes can be replaced with branches or extensions.
        loop {
            let index = queue.len() - 1;
            let borrow_node = &mut queue[index];

            let node_to_push = match borrow_node {
                Node::Empty => {
                    // Insert leaf node instead.
                    *borrow_node = Node::from_leaf(partial.clone(), value);
                    break;
                }
                borrow_node if matches!(borrow_node, Node::Leaf(_)) => {
                    // We will replace the leaf with a branch or extension most likely.
                    let leaf = std::mem::take(borrow_node);
                    let leaf = leaf.into_leaf().expect("checked above;");

                    let mut borrow_leaf = leaf.borrow_mut();

                    let old_partial = std::mem::take(&mut borrow_leaf.key);
                    let match_index = partial.common_prefix(&old_partial);

                    // Key is the same, replace value. But we need to reconstruct it as we took it out.
                    if match_index == old_partial.len() {
                        borrow_leaf.value = value;
                        borrow_leaf.key = old_partial;
                        drop(borrow_leaf);
                        *borrow_node = Node::Leaf(leaf);
                        break;
                    }

                    // Key is not the same, we need to split the leaf into a branch.
                    let mut branch = BranchNode {
                        children: empty_children(),
                        value: None,
                    };

                    // Insert old leaf.
                    let n = Node::from_leaf(
                        old_partial.offset(match_index + 1),
                        std::mem::take(&mut borrow_leaf.value),
                    );

                    branch.insert(old_partial.at(match_index), n);

                    // Insert new leaf.
                    let n = Node::from_leaf(partial.offset(match_index + 1), value);
                    branch.insert(partial.at(match_index), n);

                    // Replace current node with branch as they don't have a common prefix.
                    if match_index == 0 {
                        *borrow_node = Node::Branch(Rc::new(RefCell::new(branch)));
                    } else {
                        // Replace current node with extension.
                        *borrow_node = Node::from_extension(
                            partial.slice(0, match_index),
                            Node::Branch(Rc::new(RefCell::new(branch))),
                        );
                    }
                    break;
                }
                Node::Leaf(_) => unreachable!(),
                Node::Branch(branch) => {
                    let mut borrow_branch = branch.borrow_mut();

                    // Replace value if key is the same.
                    if partial.at(0) == 0x10 {
                        borrow_branch.value = Some(value);
                        break;
                    }

                    // Get child node on the path and push it to the queue.
                    let child = borrow_branch.children[partial.at(0)].clone();
                    partial = partial.offset(1);
                    Some(child)
                }
                borrow_node if matches!(borrow_node, Node::Extension(_)) => {
                    let ext = std::mem::take(borrow_node);
                    let ext = ext.into_extension().expect("checked above;");

                    let mut borrow_ext = ext.borrow_mut();

                    let prefix = std::mem::take(&mut borrow_ext.prefix);
                    let sub_node = borrow_ext.node.clone();
                    let match_index = partial.common_prefix(&prefix);

                    // If they don't share anything, we create a branch and insert both nodes.
                    if match_index == 0 {
                        let mut branch = BranchNode {
                            children: empty_children(),
                            value: None,
                        };
                        branch.insert(
                            prefix.at(0),
                            if prefix.len() == 1 {
                                sub_node
                            } else {
                                Node::from_extension(prefix.offset(1), sub_node)
                            },
                        );
                        *borrow_node = Node::Branch(Rc::new(RefCell::new(branch)));
                        // We just updated this node, so we need to like re-iterate it.
                        None
                    // If they share the whole prefix, we continue with the sub node.
                    } else if match_index == prefix.len() {
                        borrow_ext.prefix = prefix;
                        drop(borrow_ext);

                        partial = partial.offset(match_index);
                        *borrow_node = Node::Extension(ext);
                        Some(sub_node)
                    // If they share a part of the prefix, we adjust this node to contain same prefix, and create a new extension for the rest.
                    // This new created extension will be pushed to the queue, but on the next iteration it will be combined into branch.
                    } else {
                        borrow_ext.prefix = prefix.slice(0, match_index);
                        drop(borrow_ext);

                        *borrow_node = Node::Extension(ext);
                        let new_ext = Node::from_extension(prefix.offset(match_index), sub_node);
                        partial = partial.offset(match_index);
                        Some(new_ext)
                    }
                }
                Node::Extension(_) => unreachable!(),
            };

            if let Some(node) = node_to_push {
                queue.push(node);
            }
        }

        // We need to restore partial key as it was partly consumed in the previous loop.
        // We ignore the part of the key that wasn't consumed as it stored in the leaf now.
        let partial = partial.len();
        let mut partial = partial_key.slice(0, partial_key.len() - partial);

        // Part 2: Make links.
        // We couldn't make links over the previous loop, so we do it now.
        // Queue contains nodes from the root to the inserted/updated leaf.
        // We go from the leaf to the root, and make links. This order helps us to avoid cloning nodes.
        queue
            .into_iter()
            .rev()
            .reduce(|child, parent| {
                match &parent {
                    Node::Branch(branch) => {
                        let mut borrow_branch = branch.borrow_mut();
                        let key = partial.at(partial.len() - 1);
                        partial.pop();
                        borrow_branch.children[key] = child;
                    }
                    Node::Extension(ext) => {
                        let mut borrow_ext = ext.borrow_mut();
                        partial = partial.slice(0, partial.len() - borrow_ext.prefix.len());
                        borrow_ext.node = child;
                    }
                    _ => unreachable!(),
                };
                parent
            })
            .expect("We always have at least one node from the input")
    }

    pub fn encode_node(&self, n: Node) -> Vec<u8> {
        #[derive(Debug)]
        enum NodeOrHash {
            Node { node: Node },
            Hash(Vec<u8>),
        }

        let mut stack = vec![(NodeOrHash::Node { node: n }, 0, 0)];
        let mut counter = 0;
        loop {
            let node_or_hash = &stack[counter];
            // If we hashed everything, we are done.
            let (n, depth, parent) = (
                match &node_or_hash.0 {
                    NodeOrHash::Node { node } => node,
                    NodeOrHash::Hash(_) => {
                        if counter == 0 {
                            break;
                        }
                        counter -= 1;
                        continue;
                    }
                },
                node_or_hash.1,
                node_or_hash.2,
            );

            match n.clone() {
                // We can safely replace node with empty node hash
                Node::Empty => {
                    stack[counter].0 = NodeOrHash::Hash(vec![EMPTY_STRING_CODE]);
                    counter = parent;
                }
                // Hash leaf node and replace it with hash
                Node::Leaf(leaf) => {
                    let borrow_leaf = leaf.borrow();
                    let leaf = types::encoding::LeafEncoder {
                        key: &borrow_leaf.key.encode_compact(),
                        value: &borrow_leaf.value,
                    };
                    let hash = alloy_rlp::encode(leaf);

                    stack[counter].0 = NodeOrHash::Hash(hash);
                    counter = parent;
                }
                // It means we haven't processed all the children yet.
                // We push the child to the stack and increase the depth counter.
                Node::Branch(branch) if depth < 16 => {
                    let borrow_branch: std::cell::Ref<'_, BranchNode> = branch.borrow();
                    stack.push((
                        NodeOrHash::Node {
                            node: borrow_branch.children[depth].clone(),
                        },
                        0,
                        counter,
                    ));
                    stack[counter].1 += 1;
                    counter = stack.len() - 1;
                }
                // We have processed all the children, so we can combine and hash them.
                Node::Branch(branch) => {
                    let borrow_branch = branch.borrow();
                    let branch = types::BranchNode {
                        branches: stack
                            .drain(counter + 1..counter + 17)
                            .map(|(n, _, _)| match n {
                                NodeOrHash::Node { .. } => unreachable!(),
                                NodeOrHash::Hash(hash) => {
                                    if hash.len() == 1 {
                                        None
                                    } else {
                                        Some(H256::from_slice(&hash))
                                    }
                                }
                            })
                            .collect::<Vec<_>>()[..16]
                            .try_into()
                            .expect("We always have 16 branches"),
                        value: borrow_branch.value.clone(),
                    };
                    stack[counter].0 = NodeOrHash::Hash(alloy_rlp::encode(&branch));
                    counter = parent;
                }
                // It means we haven't processed the child yet. We push the child to the stack and increase the depth counter.
                Node::Extension(ext) if depth == 0 => {
                    let borrow_ext = ext.borrow();
                    stack.push((
                        NodeOrHash::Node {
                            node: borrow_ext.node.clone(),
                        },
                        0,
                        counter,
                    ));
                    stack[counter].1 += 1;
                    counter = stack.len() - 1;
                }
                // We have processed the child, so we can hash it.
                Node::Extension(ext) => {
                    let borrow_ext = ext.borrow();
                    let extension = types::ExtensionNode::new(
                        borrow_ext.prefix.clone(),
                        H256::from_slice(&match &stack[counter + 1].0 {
                            NodeOrHash::Node { .. } => unreachable!(),
                            NodeOrHash::Hash(hash) => hash.clone(),
                        }),
                    );
                    stack[counter].0 = NodeOrHash::Hash(alloy_rlp::encode(&extension));
                    stack.pop();
                    counter = parent;
                }
            }
        }
        // I expect that we have only one element in the stack as we combined everything.
        assert!(stack.len() == 1);

        // We return the root hash.
        match stack.pop() {
            Some((NodeOrHash::Hash(hash), _, _)) => hash,
            _ => unreachable!(),
        }
    }
}

impl IterativeTrie for PatriciaTrie {
    fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) {
        let root = self.root.clone();
        self.root =
            PatriciaTrie::insert_at_iterative(root, Nibbles::from_raw(key, true), value.to_vec());
    }

    /// Creates a proof for the given key.
    /// The proof is a list of nodes that are needed to prove that the key is in the trie.
    /// The nodes are on the path from the root to the leaf. All other subtrees are hashed.
    fn merkle_proof(&self, proving_key: Vec<u8>) -> MerkleProof {
        let mut key = Nibbles::from_raw(proving_key.clone(), true);

        let mut processing_queue = vec![self.root_node()];
        let mut proof = vec![];
        while let Some(node) = processing_queue.pop() {
            match node {
                // If we encounter a extension node, we skip common prefix and continue processing it's child
                Node::Extension(node) => {
                    let node = node.borrow();

                    key = key.offset(key.common_prefix(&node.prefix));
                    proof.push(MerkleProofNode::ExtensionNode {
                        prefix: node.prefix.clone(),
                    });
                    processing_queue.push(node.node.clone());
                }
                // if we encounter a branch node, we have to hash all the children except the one on the path to the leaf
                Node::Branch(node) => {
                    let node = node.borrow();
                    let branches = node
                        .children
                        .clone()
                        .iter()
                        .enumerate()
                        .map(|(i, node)| {
                            // We don't need to encode the node on the path to the leaf as it will be processed
                            if i == key.at(0) {
                                return None;
                            }

                            // Encode subtree it's not on the path to the leaf
                            let encoded_node = self.encode_node(node.clone());
                            // It will return a single byte if the node is empty
                            if encoded_node.len() == 1 {
                                None
                            } else {
                                Some(H256::from_slice(&encoded_node))
                            }
                        })
                        .collect::<Vec<_>>();
                    let next = node.children[key.at(0)].clone();
                    proof.push(MerkleProofNode::BranchNode {
                        branches: Box::new(
                            branches
                                .try_into()
                                .expect("branches are 16 long, so this should never fail"),
                        ),
                        index: key.at(0) as u8,
                        value: node.value.clone(),
                    });
                    processing_queue.push(next);
                    key = key.offset(1);
                }

                // We don't need to process them:
                // * Leaf node data is provided by the caller of the verification function
                // * Empty nodes are not included in the proof
                // * Hash nodes are included by merkle_generator.get_proof
                Node::Empty | Node::Leaf(_) => (),
            };
        }

        MerkleProof {
            proof,
            key: proving_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use cita_trie::Trie;
    use rand::distributions::Alphanumeric;
    use rand::{thread_rng, Rng};
    use std::collections::HashMap;
    use std::sync::Arc;

    use hasher::HasherKeccak;

    use super::{IterativeTrie, PatriciaTrie};

    #[test]
    fn recursive_crash_test() {
        let mut key = vec![0];
        let value = vec![0];

        // Cita trie can't handle this case, but we just slow :C
        let mut trie = PatriciaTrie::new();
        for _ in 0..10000 {
            trie.insert(key.clone(), value.clone());
            key.push(0u8);
        }
        assert_eq!(trie.iter().count(), 10000);
    }

    #[test]
    fn test_trie_insert() {
        let mut trie = PatriciaTrie::new();
        trie.insert(b"test".to_vec(), b"test".to_vec());
    }

    #[test]
    fn test_trie_random_insert() {
        let mut trie = PatriciaTrie::new();
        let mut cita_trie = cita_trie::PatriciaTrie::new(
            Arc::new(cita_trie::MemoryDB::new(true)),
            Arc::new(HasherKeccak::new()),
        );

        for _ in 0..1000 {
            let rand_str: String = thread_rng().sample_iter(&Alphanumeric).take(30).collect();
            let val = rand_str.as_bytes();
            trie.insert(val.to_vec(), val.to_vec());
            cita_trie.insert(val.to_vec(), val.to_vec()).unwrap();
        }
        assert!(trie.iter().zip(cita_trie.iter()).all(|(a, b)| a == b));
        assert_eq!(trie.iter().count(), 1000);
    }

    #[test]
    fn iterator_trie() {
        let mut kv = HashMap::new();
        kv.insert(b"test".to_vec(), b"test".to_vec());
        kv.insert(b"test1".to_vec(), b"test1".to_vec());
        kv.insert(b"test11".to_vec(), b"test2".to_vec());
        kv.insert(b"test14".to_vec(), b"test3".to_vec());
        kv.insert(b"test16".to_vec(), b"test4".to_vec());
        kv.insert(b"test18".to_vec(), b"test5".to_vec());
        kv.insert(b"test2".to_vec(), b"test6".to_vec());
        kv.insert(b"test23".to_vec(), b"test7".to_vec());
        kv.insert(b"test9".to_vec(), b"test8".to_vec());
        {
            let mut trie = PatriciaTrie::new();
            let mut kv = kv.clone();
            kv.iter()
                .for_each(|(k, v)| trie.insert(k.clone(), v.clone()));

            trie.iter()
                .for_each(|(k, v)| assert_eq!(kv.remove(&k).unwrap(), v));
            assert!(kv.is_empty());
        }
    }
}

#[cfg(test)]
mod merkle_proof {
    use std::sync::Arc;

    use alloy_rlp::Encodable;
    use cita_trie::{MemoryDB, PatriciaTrie, Trie};
    use hasher::HasherKeccak;

    use types::{Bloom, Receipt, TransactionReceipt, H256};

    use crate::IterativeTrie;

    fn trie_root(iter: impl Iterator<Item = (Vec<u8>, Vec<u8>)>) -> H256 {
        let mut trie =
            PatriciaTrie::new(Arc::new(MemoryDB::new(true)), Arc::new(HasherKeccak::new()));
        for (k, v) in iter {
            trie.insert(k, v).unwrap();
        }

        H256::from_slice(&trie.root().unwrap())
    }

    fn transaction_to_key_value(
        (index, transaction): (usize, TransactionReceipt),
    ) -> (Vec<u8>, Vec<u8>) {
        let mut vec = vec![];
        transaction.encode(&mut vec);
        (alloy_rlp::encode(index), vec)
    }

    #[test]
    fn test_merkle_proof() {
        let transactions: Vec<TransactionReceipt> = (0..255)
            .map(|e| TransactionReceipt {
                bloom: Bloom::new([e; 256]),
                receipt: Receipt {
                    tx_type: types::TxType::EIP1559,
                    logs: vec![],
                    cumulative_gas_used: e as u64,
                    success: true,
                },
            })
            .collect();
        const SEARCHIN_INDEX: usize = 55;
        let searching_for = transactions[SEARCHIN_INDEX].clone();
        let mut trie = crate::PatriciaTrie::new();
        for (k, v) in transactions
            .clone()
            .into_iter()
            .enumerate()
            .map(transaction_to_key_value)
        {
            trie.insert(k, v);
        }

        let proof = trie.merkle_proof(alloy_rlp::encode(SEARCHIN_INDEX));

        let restored_root = proof.merkle_root(&searching_for);

        let root = trie_root(
            transactions
                .into_iter()
                .enumerate()
                .map(transaction_to_key_value),
        );
        assert_eq!(root, restored_root);
    }
}
