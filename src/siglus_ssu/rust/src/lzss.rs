const INDEX_BITS: usize = 12;
const LENGTH_BITS: usize = 16 - INDEX_BITS;
const BREAK_EVEN: usize = 1;
const LOOK_AHEAD: usize = (1 << LENGTH_BITS) + BREAK_EVEN;
const WINDOW_SIZE: usize = 1 << INDEX_BITS;

const ROOT_NODE: usize = WINDOW_SIZE;
const UNUSED_NODE: usize = WINDOW_SIZE + 1;

#[derive(Clone, Copy)]
struct LzssNode {
    parent: u32,
    sml: u16,
    big: u16,
}

struct LzssTree {
    nodes: Box<[LzssNode; WINDOW_SIZE + 2]>,
}

impl LzssTree {
    fn new() -> Self {
        let mut nodes: Box<[LzssNode; WINDOW_SIZE + 2]> = match vec![
            LzssNode {
                parent: UNUSED_NODE as u32,
                sml: UNUSED_NODE as u16,
                big: UNUSED_NODE as u16,
            };
            WINDOW_SIZE + 2
        ]
        .into_boxed_slice()
        .try_into()
        {
            Ok(nodes) => nodes,
            Err(_) => unreachable!(),
        };
        nodes[0].parent = ROOT_NODE as u32;
        nodes[ROOT_NODE].parent = 0;
        nodes[ROOT_NODE].big = 0;
        Self { nodes }
    }

    #[inline(never)]
    fn connect(&mut self, target: usize) {
        let node = self.nodes[target];
        if node.parent == UNUSED_NODE as u32 {
            return;
        }
        let parent = node.parent as usize;
        if node.big == UNUSED_NODE as u16 {
            let next = node.sml as usize;
            self.nodes[next].parent = parent as u32;
            if self.nodes[parent].big == target as u16 {
                self.nodes[parent].big = next as u16;
            } else {
                self.nodes[parent].sml = next as u16;
            }
            self.nodes[target].parent = UNUSED_NODE as u32;
        } else if node.sml == UNUSED_NODE as u16 {
            let next = node.big as usize;
            self.nodes[next].parent = parent as u32;
            if self.nodes[parent].big == target as u16 {
                self.nodes[parent].big = next as u16;
            } else {
                self.nodes[parent].sml = next as u16;
            }
            self.nodes[target].parent = UNUSED_NODE as u32;
        } else {
            let mut next = node.sml as usize;
            while self.nodes[next].big != UNUSED_NODE as u16 {
                next = self.nodes[next].big as usize;
            }
            self.detach_predecessor(next);
            self.replace(target, next);
        }
    }

    #[inline(never)]
    fn detach_predecessor(&mut self, target: usize) {
        let node = &self.nodes[target];
        let parent = node.parent as usize;
        let next = node.sml as usize;
        self.nodes[next].parent = parent as u32;
        if self.nodes[parent].big == target as u16 {
            self.nodes[parent].big = next as u16;
        } else {
            self.nodes[parent].sml = next as u16;
        }
    }

    #[inline(never)]
    fn replace(&mut self, target: usize, next: usize) {
        let node = self.nodes[target];
        let parent = node.parent as usize;
        if self.nodes[parent].sml == target as u16 {
            self.nodes[parent].sml = next as u16;
        } else {
            self.nodes[parent].big = next as u16;
        }
        self.nodes[next] = node;
        self.nodes[node.sml as usize].parent = next as u32;
        self.nodes[node.big as usize].parent = next as u32;
        self.nodes[target].parent = UNUSED_NODE as u32;
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
        if *child != UNUSED_NODE as u16 {
            return (false, *child as usize);
        }
        *child = next as u16;
        self.nodes[next] = LzssNode {
            parent: target as u32,
            sml: UNUSED_NODE as u16,
            big: UNUSED_NODE as u16,
        };
        (true, target)
    }
}

struct LzssTreeFind<'a> {
    src: &'a [u8],
    src_index: usize,
    tree: LzssTree,
}

impl<'a> LzssTreeFind<'a> {
    fn new(src: &'a [u8]) -> Self {
        Self {
            src,
            src_index: 0,
            tree: LzssTree::new(),
        }
    }

    #[inline(always)]
    fn proc<const TRACK_MATCH: bool>(&mut self) -> (usize, usize) {
        self.src_index += 1;
        let window_top = self.src_index % WINDOW_SIZE;
        self.tree.connect(window_top);

        let mut target = self.tree.nodes[ROOT_NODE].big as usize;
        let mut match_size = 0;
        let mut match_target = window_top;

        if self.src_index >= self.src.len() {
            return (0, window_top);
        }
        let source = &self.src[self.src_index..];
        let matching_loop_cnt = LOOK_AHEAD.min(source.len());

        loop {
            let offset = self.src_index.wrapping_sub(target) % WINDOW_SIZE;
            let p2 = self.src_index.wrapping_sub(offset);

            let mut matching_counter = 0;
            let mut matching_result = 0i32;

            while matching_counter < matching_loop_cnt {
                matching_result =
                    source[matching_counter] as i32 - self.src[p2 + matching_counter] as i32;
                if matching_result != 0 {
                    break;
                }
                matching_counter += 1;
            }

            if TRACK_MATCH {
                if matching_counter > match_size {
                    match_size = matching_counter;
                    match_target = target;
                    if match_size == matching_loop_cnt {
                        self.tree.replace(target, window_top);
                        break;
                    }
                }
            } else if matching_counter == matching_loop_cnt {
                self.tree.replace(target, window_top);
                break;
            }

            let (done, new_target) =
                self.tree
                    .additional_connect(target, window_top, matching_result);
            if done {
                break;
            }
            target = new_target;
        }
        (match_size, match_target)
    }
}

pub fn pack(src: &[u8], suppress_empty_tail_group: bool) -> Vec<u8> {
    if src.is_empty() {
        return Vec::new();
    }

    let mut tree_find = LzssTreeFind::new(src);

    let mut pack_buf = vec![0u8; 8];
    let mut pack_data = [0u8; 1 + 2 * 8];
    pack_data[0] = 1;
    pack_data[1] = src[0];
    let mut pack_bit = 2u8;
    let mut pack_data_count = 2usize;
    let mut replace_cnt = 1usize;

    loop {
        for _ in 1..replace_cnt {
            tree_find.proc::<false>();
        }
        let (match_size, match_target) = tree_find.proc::<true>();

        if tree_find.src_index >= tree_find.src.len() {
            if pack_data_count > 1 || (pack_data_count == 1 && !suppress_empty_tail_group) {
                pack_buf.extend_from_slice(&pack_data[..pack_data_count]);
            }
            break;
        }

        if match_size <= BREAK_EVEN {
            replace_cnt = 1;
            pack_data[0] |= pack_bit;
            pack_data[pack_data_count] = src[tree_find.src_index];
            pack_data_count += 1;
        } else {
            replace_cnt = match_size;
            let offset = (tree_find.src_index.wrapping_sub(match_target)) % WINDOW_SIZE;
            let tok = (offset << LENGTH_BITS) | (match_size - BREAK_EVEN - 1);
            pack_data[pack_data_count] = tok as u8;
            pack_data[pack_data_count + 1] = (tok >> 8) as u8;
            pack_data_count += 2;
        }

        pack_bit <<= 1;

        if pack_bit == 0 {
            pack_buf.extend_from_slice(&pack_data[..pack_data_count]);
            pack_bit = 1;
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
