use alloy_rlp::BufMut;

use crate::H256;

#[macro_export]
macro_rules! encode {
    ($out:ident, $e:expr) => {
        $e.encode($out);
        #[cfg(feature = "debug")]
        {
            let mut vec = vec![];
            $e.encode(&mut vec);
            println!("{}: {:?}", stringify!($e), vec);
        }

    };
    ($out:ident, $e:expr, $($others:expr),+) => {
        {
            encode!($out, $e);
            encode!($out, $($others),+);
        }
    };
}

/// Given an RLP encoded node, returns either RLP(node) or RLP(keccak(RLP(node)))
pub fn rlp_node(rlp: &[u8], out: &mut dyn BufMut) {
    if rlp.len() < 32 {
        out.put_slice(rlp);
    } else {
        out.put_slice(&H256(keccak_hash::keccak(rlp).0).0);
    }
}
