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
    fn connect(&mut self, target: usize) -> Option<usize> {
        let node = self.nodes[target];
        if node.parent == UNUSED_NODE as u32 {
            return None;
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
            return Some(next);
        }
        None
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
        goes_right: bool,
    ) -> (bool, usize) {
        let child = if goes_right {
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
    previous_match_distance: usize,
    first_keys: Box<[u64; WINDOW_SIZE]>,
    prefix_roots: Vec<u16>,
}

impl<'a> LzssTreeFind<'a> {
    fn new(src: &'a [u8]) -> Self {
        let mut first_keys = Box::new([0; WINDOW_SIZE]);
        first_keys[0] = src
            .first_chunk::<8>()
            .copied()
            .map_or(0, u64::from_be_bytes);
        Self {
            src,
            src_index: 0,
            tree: LzssTree::new(),
            previous_match_distance: 0,
            first_keys,
            prefix_roots: if src.len() >= WINDOW_SIZE {
                vec![UNUSED_NODE as u16; 1 << 16]
            } else {
                Vec::new()
            },
        }
    }

    fn replace_match(&mut self, slot: usize, next: usize) {
        let first = self.first_keys[slot];
        self.first_keys[next] = first;
        if let Some(root) = self.prefix_roots.get_mut((first >> 48) as usize)
            && *root == slot as u16
        {
            *root = next as u16;
        }
        self.tree.replace(slot, next);
    }

    #[inline(always)]
    fn proc<const TRACK_MATCH: bool>(&mut self) -> (usize, usize) {
        self.src_index += 1;
        let window_top = self.src_index % WINDOW_SIZE;
        let promoted = self.tree.connect(window_top);
        if !self.prefix_roots.is_empty() {
            let old_root = &mut self.prefix_roots[(self.first_keys[window_top] >> 48) as usize];
            if *old_root == window_top as u16 {
                *old_root = UNUSED_NODE as u16;
            }
            if let Some(slot) = promoted {
                self.prefix_roots[(self.first_keys[slot] >> 48) as usize] = UNUSED_NODE as u16;
            }
        }

        let mut target = self.tree.nodes[ROOT_NODE].big as usize;
        let mut match_size = 0;
        let mut match_target = window_top;

        if self.src_index >= self.src.len() {
            return (0, window_top);
        }
        let source = &self.src[self.src_index..];
        let count = LOOK_AHEAD.min(source.len());
        let source = &source[..count];
        let distance = self.previous_match_distance;
        if count == LOOK_AHEAD && distance != 0 {
            let candidate = self.src_index - distance;
            let slot = candidate % WINDOW_SIZE;
            if self.src[candidate + LOOK_AHEAD - 1] == source[LOOK_AHEAD - 1]
                && self.tree.nodes[slot].parent != UNUSED_NODE as u32
            {
                self.replace_match(slot, window_top);
                return (LOOK_AHEAD, slot);
            }
        }
        self.previous_match_distance = 0;

        let key = source.first_chunk::<LOOK_AHEAD>().map(|source| {
            (
                u64::from_be_bytes(source[..8].try_into().unwrap()),
                u64::from_be_bytes(source[8..16].try_into().unwrap()),
                source[16],
            )
        });

        if let Some((first, _, _)) = key {
            self.first_keys[window_top] = first;
            if !self.prefix_roots.is_empty() {
                let prefix = first >> 48;
                let root = &mut self.prefix_roots[prefix as usize];
                if *root == UNUSED_NODE as u16 {
                    loop {
                        let other = self.first_keys[target] >> 48;
                        if prefix == other {
                            *root = target as u16;
                            break;
                        }
                        let (done, child) =
                            self.tree
                                .additional_connect(target, window_top, prefix > other);
                        if done {
                            *root = window_top as u16;
                            return (0, window_top);
                        }
                        target = child;
                    }
                } else {
                    target = *root as usize;
                }
            }
        }
        loop {
            let (matched, goes_right) = if let Some((first, second, last)) = key {
                let other = self.first_keys[target];
                if first != other {
                    let prefix = if TRACK_MATCH {
                        ((first ^ other).leading_zeros() / 8) as usize
                    } else {
                        0
                    };
                    (prefix, first > other)
                } else {
                    let offset = self.src_index.wrapping_sub(target) % WINDOW_SIZE;
                    let candidate_start = self.src_index.wrapping_sub(offset);
                    let candidate = self.src[candidate_start..]
                        .first_chunk::<LOOK_AHEAD>()
                        .unwrap();
                    let other = u64::from_be_bytes(candidate[8..16].try_into().unwrap());
                    if second != other {
                        let prefix = if TRACK_MATCH {
                            8 + ((second ^ other).leading_zeros() / 8) as usize
                        } else {
                            0
                        };
                        (prefix, second > other)
                    } else if last != candidate[16] {
                        (16, last > candidate[16])
                    } else {
                        (LOOK_AHEAD, false)
                    }
                }
            } else {
                let offset = self.src_index.wrapping_sub(target) % WINDOW_SIZE;
                let candidate_start = self.src_index.wrapping_sub(offset);
                let candidate = &self.src[candidate_start..candidate_start + count];
                match source.iter().zip(candidate).position(|(a, b)| a != b) {
                    Some(index) => (index, source[index] > candidate[index]),
                    None => (count, false),
                }
            };

            if matched == count {
                if count == LOOK_AHEAD {
                    self.previous_match_distance =
                        self.src_index.wrapping_sub(target) % WINDOW_SIZE;
                }
                self.replace_match(target, window_top);
                return (matched, target);
            }
            if TRACK_MATCH && matched > match_size {
                match_size = matched;
                match_target = target;
            }

            let (done, new_target) = self.tree.additional_connect(target, window_top, goes_right);
            if done {
                break;
            }
            target = new_target;
        }
        (match_size, match_target)
    }
}

pub fn pack(src: &[u8], suppress_empty_tail_group: bool) -> Result<Vec<u8>, String> {
    if src.is_empty() {
        return Ok(Vec::new());
    }
    let org_size = u32::try_from(src.len()).map_err(|_| "LZSS source size exceeds 32 bits")?;

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

    let pack_buf_size =
        u32::try_from(pack_buf.len()).map_err(|_| "LZSS packed size exceeds 32 bits")?;
    pack_buf[0..4].copy_from_slice(&pack_buf_size.to_le_bytes());
    pack_buf[4..8].copy_from_slice(&org_size.to_le_bytes());

    Ok(pack_buf)
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
                let start = out.len() - off;
                let count = ln.min(org - out.len());
                let mut copied = off.min(count);
                out.extend_from_within(start..start + copied);
                while copied < count {
                    let take = copied.min(count - copied);
                    out.extend_from_within(start..start + take);
                    copied += take;
                }
            }
            fl >>= 1;
        }
    }

    Ok(out)
}
