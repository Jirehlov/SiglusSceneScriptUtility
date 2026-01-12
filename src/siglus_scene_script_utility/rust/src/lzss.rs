//! LZSS compression/decompression implementation
//! 
//! This is a port of the Python LZSS implementation with significant
//! performance improvements using Rust's efficient memory management.

const INDEX_BITS: usize = 12;
const LENGTH_BITS: usize = 16 - INDEX_BITS;
const BREAK_EVEN: usize = 1;
const LOOK_AHEAD: usize = (1 << LENGTH_BITS) + BREAK_EVEN;
const WINDOW_SIZE: usize = 1 << INDEX_BITS;

/// Binary tree node for LZSS compression
struct LzssTree {
    size: usize,
    root: usize,
    unused: usize,
    parent: Vec<usize>,
    sml: Vec<usize>,
    big: Vec<usize>,
}

impl LzssTree {
    fn new(tree_size: usize) -> Self {
        let n = tree_size + 2;
        let unused = tree_size + 1;
        let root = tree_size;
        
        let mut parent = vec![unused; n];
        let mut sml = vec![unused; n];
        let mut big = vec![unused; n];
        
        parent[0] = root;
        parent[root] = 0;
        big[root] = 0;
        
        Self {
            size: tree_size,
            root,
            unused,
            parent,
            sml,
            big,
        }
    }

    fn connect(&mut self, target: usize) {
        if self.parent[target] == self.unused {
            return;
        }
        
        let parent = self.parent[target];
        
        if self.big[target] == self.unused {
            let nxt = self.sml[target];
            self.parent[nxt] = parent;
            if self.big[parent] == target {
                self.big[parent] = nxt;
            } else {
                self.sml[parent] = nxt;
            }
            self.parent[target] = self.unused;
        } else if self.sml[target] == self.unused {
            let nxt = self.big[target];
            self.parent[nxt] = parent;
            if self.big[parent] == target {
                self.big[parent] = nxt;
            } else {
                self.sml[parent] = nxt;
            }
            self.parent[target] = self.unused;
        } else {
            let mut nxt = self.sml[target];
            while self.big[nxt] != self.unused {
                nxt = self.big[nxt];
            }
            self.connect(nxt);
            self.replace(target, nxt);
        }
    }

    fn replace(&mut self, target: usize, nxt: usize) {
        let parent = self.parent[target];
        if self.sml[parent] == target {
            self.sml[parent] = nxt;
        } else {
            self.big[parent] = nxt;
        }
        self.parent[nxt] = self.parent[target];
        self.sml[nxt] = self.sml[target];
        self.big[nxt] = self.big[target];
        self.parent[self.sml[target]] = nxt;
        self.parent[self.big[target]] = nxt;
        self.parent[target] = self.unused;
    }

    fn additional_connect(&mut self, target: usize, nxt: usize, matching_result: i32) -> (bool, usize) {
        let child = if matching_result >= 0 {
            &mut self.big
        } else {
            &mut self.sml
        };
        
        let child_idx = child[target];
        if child_idx != self.unused {
            return (false, child_idx);
        }
        
        child[target] = nxt;
        self.parent[nxt] = target;
        self.big[nxt] = self.unused;
        self.sml[nxt] = self.unused;
        (true, target)
    }

    #[inline]
    fn get_root_big(&self) -> usize {
        self.big[self.root]
    }
}

/// Tree-based pattern finder for LZSS compression
struct LzssTreeFind<'a> {
    src: &'a [u8],
    src_cnt: usize,
    window_size: usize,
    look_ahead_size: usize,
    src_index: usize,
    match_target: usize,
    match_size: usize,
    window_top: usize,
    tree: LzssTree,
}

impl<'a> LzssTreeFind<'a> {
    fn new(src: &'a [u8], window_size: usize, look_ahead_size: usize) -> Self {
        Self {
            src,
            src_cnt: src.len(),
            window_size,
            look_ahead_size,
            src_index: 0,
            match_target: 0,
            match_size: 0,
            window_top: 0,
            tree: LzssTree::new(window_size),
        }
    }

    fn proc(&mut self, replace_cnt: usize) {
        for _ in 0..replace_cnt {
            self.src_index += 1;
            let src_page = self.src_index / self.window_size;
            self.window_top = (self.window_top + 1) % self.window_size;
            self.tree.connect(self.window_top);
            
            let mut target = self.tree.get_root_big();
            self.match_size = 0;
            
            let src_left = self.src_cnt.saturating_sub(self.src_index);
            if src_left == 0 {
                return;
            }
            
            let matching_loop_cnt = self.look_ahead_size.min(src_left);
            
            loop {
                let p1 = self.src_index;
                let mut p2 = src_page * self.window_size + target;
                if target > self.src_index % self.window_size {
                    p2 = p2.wrapping_sub(self.window_size);
                }
                
                let mut matching_counter = 0;
                let mut matching_result = 0i32;
                
                while matching_counter < matching_loop_cnt {
                    matching_result = self.src[p1 + matching_counter] as i32 
                        - self.src[p2 + matching_counter] as i32;
                    if matching_result != 0 {
                        break;
                    }
                    matching_counter += 1;
                }
                
                if matching_counter > self.match_size {
                    self.match_size = matching_counter;
                    self.match_target = target;
                    if self.match_size == matching_loop_cnt {
                        self.tree.replace(target, self.window_top);
                        break;
                    }
                }
                
                let (done, new_target) = self.tree.additional_connect(
                    target, self.window_top, matching_result
                );
                if done {
                    break;
                }
                target = new_target;
            }
        }
    }
}

/// LZSS compression
pub fn pack(src: &[u8]) -> Vec<u8> {
    if src.is_empty() {
        return Vec::new();
    }

    let mut tree_find = LzssTreeFind::new(src, WINDOW_SIZE, LOOK_AHEAD);
    
    let mut pack_buf = vec![0u8; 8];
    let mut pack_data = vec![0u8; 1 + 2 * 8];
    let mut pack_bit_count = 0usize;
    let mut pack_data_count = 1usize;
    let mut replace_cnt = 0usize;
    
    const BIT_MASK: [u8; 8] = [1, 2, 4, 8, 16, 32, 64, 128];

    loop {
        // make_pack_data inline
        if tree_find.src_index >= tree_find.src_cnt {
            pack_buf.extend_from_slice(&pack_data[..pack_data_count]);
            break;
        }
        
        if replace_cnt > 0 {
            tree_find.proc(replace_cnt);
        }
        
        if tree_find.src_index >= tree_find.src_cnt {
            pack_buf.extend_from_slice(&pack_data[..pack_data_count]);
            break;
        }
        
        if tree_find.match_size <= BREAK_EVEN {
            replace_cnt = 1;
            pack_data[0] |= BIT_MASK[pack_bit_count];
            pack_data[pack_data_count] = src[tree_find.src_index];
            pack_data_count += 1;
        } else {
            replace_cnt = tree_find.match_size;
            let offset = (tree_find.window_top.wrapping_sub(tree_find.match_target)) % WINDOW_SIZE;
            let tok = (offset << LENGTH_BITS) | (tree_find.match_size - BREAK_EVEN - 1);
            pack_data[pack_data_count] = tok as u8;
            pack_data[pack_data_count + 1] = (tok >> 8) as u8;
            pack_data_count += 2;
        }
        
        pack_bit_count += 1;
        
        if pack_bit_count == 8 {
            pack_buf.extend_from_slice(&pack_data[..pack_data_count]);
            pack_bit_count = 0;
            pack_data_count = 1;
            pack_data[0] = 0;
        }
    }

    // Write header
    let pack_buf_size = pack_buf.len() as u32;
    let org_size = src.len() as u32;
    pack_buf[0..4].copy_from_slice(&pack_buf_size.to_le_bytes());
    pack_buf[4..8].copy_from_slice(&org_size.to_le_bytes());
    
    pack_buf
}

/// LZSS decompression
pub fn unpack(src: &[u8]) -> Vec<u8> {
    if src.len() < 8 {
        return Vec::new();
    }
    
    let org = u32::from_le_bytes([src[4], src[5], src[6], src[7]]) as usize;
    if org == 0 {
        return Vec::new();
    }
    
    let mut out = Vec::with_capacity(org);
    let mut si = 8;
    
    while out.len() < org && si < src.len() {
        let mut fl = src[si];
        si += 1;
        
        for _ in 0..8 {
            if out.len() >= org {
                break;
            }
            
            if fl & 1 != 0 {
                if si < src.len() {
                    out.push(src[si]);
                    si += 1;
                }
            } else {
                if si + 1 >= src.len() {
                    break;
                }
                let tok = (src[si] as usize) | ((src[si + 1] as usize) << 8);
                si += 2;
                let off = tok >> 4;
                let ln = (tok & 0xF) + 2;
                let st = out.len().wrapping_sub(off);
                
                for j in 0..ln {
                    if out.len() >= org {
                        break;
                    }
                    let idx = st.wrapping_add(j);
                    if idx < out.len() {
                        out.push(out[idx]);
                    }
                }
            }
            fl >>= 1;
        }
    }
    
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let data = b"Hello, World! This is a test of LZSS compression. Hello, World!";
        let packed = pack(data);
        let unpacked = unpack(&packed);
        assert_eq!(data.as_slice(), unpacked.as_slice());
    }

    #[test]
    fn test_empty() {
        assert!(pack(&[]).is_empty());
        assert!(unpack(&[]).is_empty());
    }
}
