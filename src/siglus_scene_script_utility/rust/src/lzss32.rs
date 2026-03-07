use std::convert::TryInto;

const INDEX_BITS: usize = 12;
const BREAK_EVEN: usize = 0;
const LENGTH_BITS: usize = 16 - INDEX_BITS;
const LOOK_AHEAD: usize = (1 << LENGTH_BITS) + BREAK_EVEN;
const WINDOW_SIZE: usize = 1 << INDEX_BITS;

struct LzssTree {
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
        let sml = vec![unused; n];
        let mut big = vec![unused; n];
        parent[0] = root;
        parent[root] = 0;
        big[root] = 0;
        Self {
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
            let next = self.sml[target];
            self.parent[next] = parent;
            if self.big[parent] == target {
                self.big[parent] = next;
            } else {
                self.sml[parent] = next;
            }
            self.parent[target] = self.unused;
        } else if self.sml[target] == self.unused {
            let next = self.big[target];
            self.parent[next] = parent;
            if self.big[parent] == target {
                self.big[parent] = next;
            } else {
                self.sml[parent] = next;
            }
            self.parent[target] = self.unused;
        } else {
            let mut next = self.sml[target];
            while self.big[next] != self.unused {
                next = self.big[next];
            }
            self.connect(next);
            self.replace(target, next);
        }
    }

    fn replace(&mut self, target: usize, next: usize) {
        let parent = self.parent[target];
        if self.sml[parent] == target {
            self.sml[parent] = next;
        } else {
            self.big[parent] = next;
        }
        self.parent[next] = self.parent[target];
        self.sml[next] = self.sml[target];
        self.big[next] = self.big[target];
        self.parent[self.sml[target]] = next;
        self.parent[self.big[target]] = next;
        self.parent[target] = self.unused;
    }

    fn additional_connect(
        &mut self,
        target: usize,
        next: usize,
        matching_result: i64,
    ) -> (bool, usize) {
        let child = if matching_result >= 0 {
            &mut self.big
        } else {
            &mut self.sml
        };
        let child_idx = child[target];
        if child_idx != self.unused {
            return (false, child_idx);
        }
        child[target] = next;
        self.parent[next] = target;
        self.big[next] = self.unused;
        self.sml[next] = self.unused;
        (true, target)
    }

    fn get_root_big(&self) -> usize {
        self.big[self.root]
    }
}

struct LzssTreeFind<'a> {
    src: &'a [u32],
    src_cnt: usize,
    window_size: usize,
    max_match_len: usize,
    src_index: usize,
    match_target: usize,
    match_size: usize,
    window_top: usize,
    tree: LzssTree,
}

impl<'a> LzssTreeFind<'a> {
    fn new(src: &'a [u32], window_size: usize, look_ahead_size: usize, level: usize) -> Self {
        let max_match_len = std::cmp::max(2, std::cmp::min(level, look_ahead_size));
        Self {
            src,
            src_cnt: src.len(),
            window_size,
            max_match_len,
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
            let mut matching_loop_cnt = self.max_match_len;
            let src_left = self.src_cnt.saturating_sub(self.src_index);
            if src_left == 0 {
                return;
            }
            if matching_loop_cnt > src_left {
                matching_loop_cnt = src_left;
            }
            loop {
                let p1 = self.src_index;
                let mut p2 = src_page * self.window_size + target;
                if target > self.src_index % self.window_size {
                    p2 -= self.window_size;
                }
                let mut matching_counter = 0usize;
                let mut matching_result = 0i64;
                while matching_counter < matching_loop_cnt {
                    matching_result = self.src[p1 + matching_counter] as i64
                        - self.src[p2 + matching_counter] as i64;
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
                let (done, next_target) =
                    self.tree
                        .additional_connect(target, self.window_top, matching_result);
                if done {
                    break;
                }
                target = next_target;
            }
        }
    }
}

pub fn pack(src: &[u8]) -> Result<Vec<u8>, String> {
    if src.is_empty() {
        return Ok(Vec::new());
    }
    if src.len() % 4 != 0 {
        return Err("lzss32: source size is not a multiple of 4".to_string());
    }
    let src_cnt = src.len() / 4;
    if src_cnt == 0 {
        return Ok(Vec::new());
    }
    let mut dwords = Vec::with_capacity(src_cnt);
    for chunk in src.chunks_exact(4) {
        let arr: [u8; 4] = chunk
            .try_into()
            .map_err(|_| "lzss32: bad chunk".to_string())?;
        dwords.push(u32::from_le_bytes(arr));
    }
    let mut tree_find = LzssTreeFind::new(&dwords, WINDOW_SIZE, LOOK_AHEAD, LOOK_AHEAD);
    let mut pack_buf = vec![0u8; 8];
    let mut pack_data = [0u8; 1 + 3 * 8];
    pack_data[0] = 0;
    let mut pack_bit_count = 0usize;
    let mut pack_data_count = 1usize;
    let mut replace_cnt = 0usize;
    let bit_mask = [1u8, 2, 4, 8, 16, 32, 64, 128];

    loop {
        if tree_find.src_index >= tree_find.src_cnt {
            break;
        }
        if replace_cnt > 0 {
            tree_find.proc(replace_cnt);
        }
        if tree_find.src_index >= tree_find.src_cnt {
            break;
        }
        if tree_find.match_size <= BREAK_EVEN {
            replace_cnt = 1;
            pack_data[0] |= bit_mask[pack_bit_count];
            let v = dwords[tree_find.src_index].to_le_bytes();
            pack_data[pack_data_count] = v[0];
            pack_data[pack_data_count + 1] = v[1];
            pack_data[pack_data_count + 2] = v[2];
            pack_data_count += 3;
        } else {
            replace_cnt = tree_find.match_size;
            let mut tok = ((tree_find.window_top + WINDOW_SIZE - tree_find.match_target)
                % WINDOW_SIZE)
                << LENGTH_BITS;
            tok |= tree_find.match_size - BREAK_EVEN - 1;
            let b = (tok as u16).to_le_bytes();
            pack_data[pack_data_count] = b[0];
            pack_data[pack_data_count + 1] = b[1];
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

    if pack_data_count > 1 {
        pack_buf.extend_from_slice(&pack_data[..pack_data_count]);
    }

    let arc = pack_buf.len() as u32;
    let org = src.len() as u32;
    pack_buf[0..4].copy_from_slice(&arc.to_le_bytes());
    pack_buf[4..8].copy_from_slice(&org.to_le_bytes());
    Ok(pack_buf)
}
