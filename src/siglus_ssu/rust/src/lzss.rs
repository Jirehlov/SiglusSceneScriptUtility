const INDEX_BITS: usize = 12;
const LENGTH_BITS: usize = 16 - INDEX_BITS;
const BREAK_EVEN: usize = 1;
const LOOK_AHEAD: usize = (1 << LENGTH_BITS) + BREAK_EVEN;
const WINDOW_SIZE: usize = 1 << INDEX_BITS;

const ROOT_NODE: usize = WINDOW_SIZE;
const UNUSED_NODE: usize = WINDOW_SIZE + 1;

#[derive(Clone, Copy)]
struct LzssNode {
    parent: usize,
    sml: usize,
    big: usize,
}

struct LzssTree {
    nodes: Vec<LzssNode>,
}

impl LzssTree {
    fn new() -> Self {
        let mut nodes = vec![
            LzssNode {
                parent: UNUSED_NODE,
                sml: UNUSED_NODE,
                big: UNUSED_NODE,
            };
            WINDOW_SIZE + 2
        ];
        nodes[0].parent = ROOT_NODE;
        nodes[ROOT_NODE].parent = 0;
        nodes[ROOT_NODE].big = 0;
        Self { nodes }
    }

    fn connect(&mut self, target: usize) {
        let node = self.nodes[target];
        if node.parent == UNUSED_NODE {
            return;
        }
        let parent = node.parent;
        if node.big == UNUSED_NODE {
            let next = node.sml;
            self.nodes[next].parent = parent;
            if self.nodes[parent].big == target {
                self.nodes[parent].big = next;
            } else {
                self.nodes[parent].sml = next;
            }
            self.nodes[target].parent = UNUSED_NODE;
        } else if node.sml == UNUSED_NODE {
            let next = node.big;
            self.nodes[next].parent = parent;
            if self.nodes[parent].big == target {
                self.nodes[parent].big = next;
            } else {
                self.nodes[parent].sml = next;
            }
            self.nodes[target].parent = UNUSED_NODE;
        } else {
            let mut next = node.sml;
            while self.nodes[next].big != UNUSED_NODE {
                next = self.nodes[next].big;
            }
            self.connect(next);
            self.replace(target, next);
        }
    }

    fn replace(&mut self, target: usize, next: usize) {
        let node = self.nodes[target];
        let parent = node.parent;
        if self.nodes[parent].sml == target {
            self.nodes[parent].sml = next;
        } else {
            self.nodes[parent].big = next;
        }
        self.nodes[next] = node;
        self.nodes[node.sml].parent = next;
        self.nodes[node.big].parent = next;
        self.nodes[target].parent = UNUSED_NODE;
    }

    fn additional_connect(
        &mut self,
        target: usize,
        next: usize,
        matching_result: i32,
    ) -> (bool, usize) {
        let child = if matching_result >= 0 {
            &mut self.nodes[target].big
        } else {
            &mut self.nodes[target].sml
        };
        if *child != UNUSED_NODE {
            return (false, *child);
        }
        *child = next;
        self.nodes[next] = LzssNode {
            parent: target,
            sml: UNUSED_NODE,
            big: UNUSED_NODE,
        };
        (true, target)
    }
}

struct LzssTreeFind<'a> {
    src: &'a [u8],
    src_cnt: usize,
    src_index: usize,
    match_target: usize,
    match_size: usize,
    window_top: usize,
    tree: LzssTree,
}

impl<'a> LzssTreeFind<'a> {
    fn new(src: &'a [u8]) -> Self {
        Self {
            src,
            src_cnt: src.len(),
            src_index: 0,
            match_target: 0,
            match_size: 0,
            window_top: 0,
            tree: LzssTree::new(),
        }
    }

    fn proc(&mut self, replace_cnt: usize) {
        for _ in 0..replace_cnt {
            self.src_index += 1;
            let src_page = self.src_index / WINDOW_SIZE;
            self.window_top = (self.window_top + 1) % WINDOW_SIZE;
            self.tree.connect(self.window_top);

            let mut target = self.tree.nodes[ROOT_NODE].big;
            self.match_size = 0;

            let src_left = self.src_cnt.saturating_sub(self.src_index);
            if src_left == 0 {
                return;
            }

            let matching_loop_cnt = LOOK_AHEAD.min(src_left);

            loop {
                let p1 = self.src_index;
                let mut p2 = src_page * WINDOW_SIZE + target;
                if target > self.src_index % WINDOW_SIZE {
                    p2 = p2.wrapping_sub(WINDOW_SIZE);
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

                let (done, new_target) =
                    self.tree
                        .additional_connect(target, self.window_top, matching_result);
                if done {
                    break;
                }
                target = new_target;
            }
        }
    }
}

pub fn pack(src: &[u8], suppress_empty_tail_group: bool) -> Vec<u8> {
    if src.is_empty() {
        return Vec::new();
    }

    let mut tree_find = LzssTreeFind::new(src);

    let mut pack_buf = vec![0u8; 8];
    let mut pack_data = [0u8; 1 + 2 * 8];
    let mut pack_bit_count = 0usize;
    let mut pack_data_count = 1usize;
    let mut replace_cnt = 0usize;

    const BIT_MASK: [u8; 8] = [1, 2, 4, 8, 16, 32, 64, 128];

    loop {
        if tree_find.src_index >= tree_find.src_cnt {
            if pack_data_count > 1 || (pack_data_count == 1 && !suppress_empty_tail_group) {
                pack_buf.extend_from_slice(&pack_data[..pack_data_count]);
            }
            break;
        }

        if replace_cnt > 0 {
            tree_find.proc(replace_cnt);
        }

        if tree_find.src_index >= tree_find.src_cnt {
            if pack_data_count > 1 || (pack_data_count == 1 && !suppress_empty_tail_group) {
                pack_buf.extend_from_slice(&pack_data[..pack_data_count]);
            }
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

    let pack_buf_size = pack_buf.len() as u32;
    let org_size = src.len() as u32;
    pack_buf[0..4].copy_from_slice(&pack_buf_size.to_le_bytes());
    pack_buf[4..8].copy_from_slice(&org_size.to_le_bytes());

    pack_buf
}

pub fn unpack(src: &[u8]) -> Result<Vec<u8>, String> {
    if src.is_empty() {
        return Ok(Vec::new());
    }
    if src.len() < 8 {
        return Err("lzss short".to_string());
    }

    let org = u32::from_le_bytes([src[4], src[5], src[6], src[7]]) as usize;
    if org == 0 {
        return Ok(Vec::new());
    }

    let mut out = Vec::new();
    let mut si = 8;

    while out.len() < org {
        if si >= src.len() {
            return Err("lzss eof".to_string());
        }
        let mut fl = src[si];
        si += 1;

        for _ in 0..8 {
            if out.len() >= org {
                break;
            }

            if fl & 1 != 0 {
                if si >= src.len() {
                    return Err("lzss eof".to_string());
                }
                out.push(src[si]);
                si += 1;
            } else {
                if si + 2 > src.len() {
                    return Err("lzss eof".to_string());
                }
                let tok = (src[si] as usize) | ((src[si + 1] as usize) << 8);
                si += 2;
                let off = tok >> 4;
                let ln = (tok & 0xF) + 2;
                if off == 0 {
                    return Err("lzss off0".to_string());
                }
                if off > out.len() {
                    return Err("lzss back".to_string());
                }
                let st = out.len() - off;

                for j in 0..ln {
                    if out.len() >= org {
                        break;
                    }
                    let idx = st + j;
                    out.push(out[idx]);
                }
            }
            fl >>= 1;
        }
    }

    Ok(out)
}
