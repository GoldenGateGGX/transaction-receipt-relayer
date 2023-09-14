use std::cell::RefCell;
use std::rc::Rc;

use types::Nibbles;

#[derive(Debug, Clone, Default)]
pub enum Node {
    #[default]
    Empty,
    Leaf(Rc<RefCell<LeafNode>>),
    Extension(Rc<RefCell<ExtensionNode>>),
    Branch(Rc<RefCell<BranchNode>>),
}

impl Node {
    pub fn from_leaf(key: Nibbles, value: Vec<u8>) -> Self {
        let leaf = Rc::new(RefCell::new(LeafNode { key, value }));
        Node::Leaf(leaf)
    }

    pub fn from_branch(children: [Node; 16], value: Option<Vec<u8>>) -> Self {
        let branch = Rc::new(RefCell::new(BranchNode { children, value }));
        Node::Branch(branch)
    }

    pub fn from_extension(prefix: Nibbles, node: Node) -> Self {
        let ext = Rc::new(RefCell::new(ExtensionNode { prefix, node }));
        Node::Extension(ext)
    }

    pub fn into_leaf(self) -> Option<Rc<RefCell<LeafNode>>> {
        match self {
            Node::Leaf(leaf) => Some(leaf),
            _ => None,
        }
    }

    pub fn into_extension(self) -> Option<Rc<RefCell<ExtensionNode>>> {
        match self {
            Node::Extension(ext) => Some(ext),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct LeafNode {
    pub key: Nibbles,
    pub value: Vec<u8>,
}

#[derive(Debug)]
pub struct BranchNode {
    pub children: [Node; 16],
    pub value: Option<Vec<u8>>,
}

impl BranchNode {
    pub fn insert(&mut self, i: usize, n: Node) {
        if i == 16 {
            match n {
                Node::Leaf(leaf) => {
                    self.value = Some(leaf.borrow().value.clone());
                }
                _ => panic!("The n must be leaf node"),
            }
        } else {
            self.children[i] = n
        }
    }
}

#[derive(Debug)]
pub struct ExtensionNode {
    pub prefix: Nibbles,
    pub node: Node,
}

#[derive(Debug)]
pub struct HashNode {
    pub hash: Vec<u8>,
}

pub fn empty_children() -> [Node; 16] {
    [
        Node::Empty,
        Node::Empty,
        Node::Empty,
        Node::Empty,
        Node::Empty,
        Node::Empty,
        Node::Empty,
        Node::Empty,
        Node::Empty,
        Node::Empty,
        Node::Empty,
        Node::Empty,
        Node::Empty,
        Node::Empty,
        Node::Empty,
        Node::Empty,
    ]
}
