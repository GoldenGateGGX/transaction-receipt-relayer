use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::sync::Arc;

use hasher::Hasher;
use rlp::RlpStream;

use crate::nibbles::Nibbles;
use crate::node::{empty_children, BranchNode, Node};

pub trait IterativeTrie<H: Hasher> {
    fn insert(&mut self, key: Vec<u8>, value: Vec<u8>);
}

#[derive(Debug)]
pub struct PatriciaTrie<H>
where
    H: Hasher,
{
    root: Node,

    hasher: Arc<H>,

    cache: RefCell<HashMap<Vec<u8>, Vec<u8>>>,
    gen_keys: RefCell<HashSet<Vec<u8>>>,
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

impl<H> PatriciaTrie<H>
where
    H: Hasher,
{
    pub fn iter(&self) -> TrieIterator {
        let nodes = vec![self.root.clone().into()];
        TrieIterator {
            nibble: Nibbles::from_raw(vec![], false),
            nodes,
        }
    }
    pub fn new(hasher: Arc<H>) -> Self {
        Self {
            root: Node::Empty,

            cache: RefCell::new(HashMap::new()),
            gen_keys: RefCell::new(HashSet::new()),

            hasher,
        }
    }
}

impl<H> PatriciaTrie<H>
where
    H: Hasher,
{
    pub fn root_node(&self) -> Node {
        self.root.clone()
    }

    fn insert_at_iterative(n: Node, partial_key: Nibbles, value: Vec<u8>) -> Node {
        let mut queue = vec![n];
        let mut counter = 0;
        let mut partial = partial_key.clone();

        // Part 1: Find place to insert, or replace value.
        // Meanwhile, nodes can be replaced with branches or extensions.
        loop {
            match queue[counter].clone() {
                Node::Empty => {
                    // Insert leaf node instead.
                    queue[counter] = Node::from_leaf(partial.clone(), value);
                    break;
                }
                Node::Leaf(leaf) => {
                    let mut borrow_leaf = leaf.borrow_mut();

                    let old_partial = &borrow_leaf.key;
                    let match_index = partial.common_prefix(old_partial);

                    // Key is the same, replace value.
                    if match_index == old_partial.len() {
                        borrow_leaf.value = value;
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
                        borrow_leaf.value.clone(),
                    );

                    branch.insert(old_partial.at(match_index), n);

                    // Insert new leaf.
                    let n = Node::from_leaf(partial.offset(match_index + 1), value);
                    branch.insert(partial.at(match_index), n);

                    // Replace current node with branch as they don't have a common prefix.
                    if match_index == 0 {
                        queue[counter] = Node::Branch(Rc::new(RefCell::new(branch)));
                    } else {
                        // Replace current node with extension.
                        queue[counter] = Node::from_extension(
                            partial.slice(0, match_index),
                            Node::Branch(Rc::new(RefCell::new(branch))),
                        );
                    }
                    break;
                }
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
                    queue.push(child);
                    counter += 1;
                }
                Node::Extension(ext) => {
                    let mut borrow_ext = ext.borrow_mut();

                    let prefix = &borrow_ext.prefix;
                    let sub_node = borrow_ext.node.clone();
                    let match_index = partial.common_prefix(prefix);

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
                        let node = Node::Branch(Rc::new(RefCell::new(branch)));
                        queue[counter] = node;
                    // If they share the whole prefix, we continue with the sub node.
                    } else if match_index == prefix.len() {
                        partial = partial.offset(match_index);
                        queue.push(sub_node);
                        counter += 1;
                    // If they share a part of the prefix, we adjust this node to contain same prefix, and create a new extension for the rest.
                    // This new created extension will be pushed to the queue, but on the next iteration it will be combined into branch.
                    } else {
                        let new_ext = Node::from_extension(prefix.offset(match_index), sub_node);
                        partial = partial.offset(match_index);
                        queue.push(new_ext);
                        counter += 1;

                        borrow_ext.prefix = prefix.slice(0, match_index);
                    }
                }
            }
        }

        // We need to restore partial key as it was partly consumed in the previous loop.
        // We ignore the part of the key that wasn't consumed as it stored in the leaf now.
        let partial = partial.len();
        let mut partial = partial_key.slice(0, partial_key.len() - partial);

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
        let data = self.encode_raw(n.clone());
        // Nodes smaller than 32 bytes are stored inside their parent,
        // Nodes equal to 32 bytes are returned directly
        if data.len() < H::LENGTH {
            data
        } else {
            let hash = self.hasher.digest(&data);
            self.cache.borrow_mut().insert(hash.clone(), data);

            self.gen_keys.borrow_mut().insert(hash.clone());
            hash
        }
    }

    pub fn encode_raw(&self, n: Node) -> Vec<u8> {
        match n {
            Node::Empty => rlp::NULL_RLP.to_vec(),
            Node::Leaf(leaf) => {
                let borrow_leaf = leaf.borrow();

                let mut stream = RlpStream::new_list(2);
                stream.append(&borrow_leaf.key.encode_compact());
                stream.append(&borrow_leaf.value);
                stream.out().to_vec()
            }
            Node::Branch(branch) => {
                let borrow_branch = branch.borrow();

                let mut stream = RlpStream::new_list(17);
                for i in 0..16 {
                    let n = borrow_branch.children[i].clone();
                    let data = self.encode_node(n);
                    if data.len() == H::LENGTH {
                        stream.append(&data);
                    } else {
                        stream.append_raw(&data, 1);
                    }
                }

                match &borrow_branch.value {
                    Some(v) => stream.append(v),
                    None => stream.append_empty_data(),
                };
                stream.out().to_vec()
            }
            Node::Extension(ext) => {
                let borrow_ext = ext.borrow();

                let mut stream = RlpStream::new_list(2);
                stream.append(&borrow_ext.prefix.encode_compact());
                let data = self.encode_node(borrow_ext.node.clone());
                if data.len() == H::LENGTH {
                    stream.append(&data);
                } else {
                    stream.append_raw(&data, 1);
                }
                stream.out().to_vec()
            }
        }
    }
}

impl<H: Hasher> IterativeTrie<H> for PatriciaTrie<H> {
    fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) {
        let root = self.root.clone();
        self.root = PatriciaTrie::<H>::insert_at_iterative(
            root,
            Nibbles::from_raw(key, true),
            value.to_vec(),
        );
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
        let mut trie = PatriciaTrie::new(Arc::new(HasherKeccak::new()));
        for _ in 0..10000 {
            trie.insert(key.clone(), value.clone());
            key.push(0u8);
        }
        assert_eq!(trie.iter().count(), 10000);
    }

    #[test]
    fn test_trie_insert() {
        let mut trie = PatriciaTrie::new(Arc::new(HasherKeccak::new()));
        trie.insert(b"test".to_vec(), b"test".to_vec());
    }

    #[test]
    fn test_trie_random_insert() {
        let mut trie = PatriciaTrie::new(Arc::new(HasherKeccak::new()));
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
            let mut trie = PatriciaTrie::new(Arc::new(HasherKeccak::new()));
            let mut kv = kv.clone();
            kv.iter()
                .for_each(|(k, v)| trie.insert(k.clone(), v.clone()));

            trie.iter()
                .for_each(|(k, v)| assert_eq!(kv.remove(&k).unwrap(), v));
            assert!(kv.is_empty());
        }
    }
}
