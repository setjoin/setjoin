//! Pure-MIT in-crate Tantivy tokenizers with lazy `OnceLock<Arc<_>>` dictionary loading:
//! - `zh_jieba`: wraps `jieba_rs::Jieba` (MIT, zero `zstd-sys`, zero `CC-BY-SA`)
//! - `cjk_bigram`: pure-MIT CJK unigram + adjacent bigram tokenizer over Han/Kana/Hangul runs
//! - `ident_exact`: whole lowercased non-whitespace tokens + delimiter-split sub-tokens

use jieba_rs::Jieba;
use std::io::Cursor;
use std::path::Path;
use std::sync::{Arc, OnceLock};
use tantivy::tokenizer::{Token, TokenStream, Tokenizer};

/// Tokenizer name for Chinese word segmentation + ASCII normalization.
pub const ZH_JIEBA_TOKENIZER: &str = "zh_jieba";

/// Tokenizer name for Han/Kana/Hangul unigram + adjacent bigram recall.
pub const CJK_BIGRAM_TOKENIZER: &str = "cjk_bigram";

/// Tokenizer name for exact emails, filenames, UUIDs, and delimiter sub-tokens.
pub const IDENT_EXACT_TOKENIZER: &str = "ident_exact";

/// Compact pure-MIT core Chinese vocabulary supplementing Jieba's compiled-in HMM model.
/// Optional full external dictionary files may also be configured via `SETJOIN_SEARCH_ZH_DICT_PATH`.
const EMBEDDED_MIT_ZH_DICT: &str = "\
人工智能 5000 n
机器学习 4000 n
深度学习 3500 n
邮件 8000 n
邮件系统 3000 n
电子邮箱 3000 n
附件 6000 n
发票 6000 n
合同 6000 n
审批 6000 v
报销 5000 v
会议 8000 n
日程 6000 n
联系人 5000 n
云盘 6000 n
文档 7000 n
文件夹 5000 n
搜索 8000 v
搜索引擎 5000 n
安全 7000 a
加密 6000 v
审计 6000 v
合规 6000 n
归档 5000 v
备份 6000 v
恢复 6000 v
权限 6000 n
管理员 6000 n
部门 5000 n
项目 7000 n
进度 5000 n
汇报 5000 v
周报 5000 n
月报 5000 n
年度 5000 n
财务 6000 n
采购 5000 v
客户 7000 n
北京 9000 ns
上海 9000 ns
深圳 8000 ns
杭州 7000 ns
广州 7000 ns
清华大学 5000 nt
北京大学 5000 nt
人民 8000 n
银行 8000 n
中华人民共和国 5000 ns
";

static GLOBAL_JIEBA: OnceLock<Arc<Jieba>> = OnceLock::new();

/// Returns `true` if the lazy Jieba segmenter has been initialized in this process.
/// Tier-1-only deployments never initialize it and pay zero RAM/startup cost.
#[must_use]
pub fn is_jieba_initialized() -> bool {
    GLOBAL_JIEBA.get().is_some()
}

/// Lazily load and share the `Jieba` instance behind `OnceLock<Arc<Jieba>>`.
#[must_use]
pub fn lazy_jieba(external_dict_path: Option<&Path>) -> Arc<Jieba> {
    Arc::clone(GLOBAL_JIEBA.get_or_init(|| Arc::new(build_jieba(external_dict_path))))
}

fn build_jieba(external_dict_path: Option<&Path>) -> Jieba {
    let mut jieba = match external_dict_path.and_then(|p| std::fs::read(p).ok()) {
        Some(bytes) => {
            let mut cursor = Cursor::new(bytes);
            Jieba::with_dict(&mut cursor).unwrap_or_else(|_| load_embedded_jieba())
        }
        None => load_embedded_jieba(),
    };
    // Ensure embedded MIT enterprise terms are always available even if external dict lacked them.
    let mut cursor = Cursor::new(EMBEDDED_MIT_ZH_DICT.as_bytes());
    let _ = jieba.load_dict(&mut cursor);
    jieba
}

fn load_embedded_jieba() -> Jieba {
    let mut cursor = Cursor::new(EMBEDDED_MIT_ZH_DICT.as_bytes());
    Jieba::with_dict(&mut cursor).unwrap_or_else(|_| Jieba::empty())
}

/// Returns `true` if `ch` is a CJK (Han, Hiragana, Katakana, or Hangul) codepoint.
#[must_use]
pub const fn is_cjk_char(ch: char) -> bool {
    matches!(
        ch,
        '\u{3400}'..='\u{4DBF}'    // CJK Unified Ideographs Extension A
        | '\u{4E00}'..='\u{9FFF}'  // CJK Unified Ideographs
        | '\u{F900}'..='\u{FAFF}'  // CJK Compatibility Ideographs
        | '\u{20000}'..='\u{2EBEF}'// CJK Extensions B..F
        | '\u{3040}'..='\u{309F}'  // Hiragana
        | '\u{30A0}'..='\u{30FF}'  // Katakana
        | '\u{31F0}'..='\u{31FF}'  // Katakana Phonetic Extensions
        | '\u{FF65}'..='\u{FF9F}'  // Halfwidth Katakana
        | '\u{1100}'..='\u{11FF}'  // Hangul Jamo
        | '\u{3130}'..='\u{318F}'  // Hangul Compatibility Jamo
        | '\u{AC00}'..='\u{D7AF}'  // Hangul Syllables
    )
}

/// Normalize fullwidth ASCII forms (`！`..`～`) to standard ASCII and lowercase.
#[must_use]
pub fn normalize_char(ch: char) -> char {
    let code = ch as u32;
    if (0xFF01..=0xFF5E).contains(&code) {
        char::from_u32(code - 0xFEE0)
            .map(|c| c.to_ascii_lowercase())
            .unwrap_or(ch)
    } else if ch.is_ascii_uppercase() {
        ch.to_ascii_lowercase()
    } else {
        ch
    }
}

/// Reusable pre-computed token stream implementing [`tantivy::tokenizer::TokenStream`].
pub struct VecTokenStream {
    tokens: Vec<Token>,
    index: usize,
    current: Token,
}

impl VecTokenStream {
    #[must_use]
    pub fn new(tokens: Vec<Token>) -> Self {
        Self {
            tokens,
            index: 0,
            current: Token::default(),
        }
    }
}

impl TokenStream for VecTokenStream {
    fn advance(&mut self) -> bool {
        if let Some(tok) = self.tokens.get(self.index) {
            self.current = tok.clone();
            self.index += 1;
            true
        } else {
            false
        }
    }

    fn token(&self) -> &Token {
        &self.current
    }

    fn token_mut(&mut self) -> &mut Token {
        &mut self.current
    }
}

/// Thin pure-MIT `tantivy::tokenizer::Tokenizer` adapter wrapping `jieba_rs::Jieba`.
#[derive(Clone, Default)]
pub struct ZhJiebaTokenizer {
    external_dict_path: Option<Arc<std::path::PathBuf>>,
}

impl ZhJiebaTokenizer {
    #[must_use]
    pub fn new(external_dict_path: Option<std::path::PathBuf>) -> Self {
        Self {
            external_dict_path: external_dict_path.map(Arc::new),
        }
    }

    /// Tokenize text into normalized lowercase terms (for query construction and tests).
    #[must_use]
    pub fn tokenize_terms(&self, text: &str) -> Vec<String> {
        let mut clone = self.clone();
        let mut stream = clone.token_stream(text);
        let mut out = Vec::new();
        while stream.advance() {
            out.push(stream.token().text.clone());
        }
        out
    }
}

impl Tokenizer for ZhJiebaTokenizer {
    type TokenStream<'a> = VecTokenStream;

    fn token_stream<'a>(&'a mut self, text: &'a str) -> Self::TokenStream<'a> {
        if text.is_empty() {
            return VecTokenStream::new(Vec::new());
        }
        let jieba = lazy_jieba(self.external_dict_path.as_deref().map(Path::new));
        let mut tokens = Vec::new();
        let mut position = 0usize;
        let mut cursor = 0usize;

        for piece in jieba.cut_for_search(text, true) {
            let trimmed = piece.word.trim();
            if trimmed.is_empty() {
                continue;
            }
            let normalized: String = trimmed
                .chars()
                .map(normalize_char)
                .filter(|c| c.is_alphanumeric() || is_cjk_char(*c))
                .collect();
            if normalized.is_empty() {
                continue;
            }
            let offset_from = text
                .get(cursor..)
                .and_then(|rest| rest.find(trimmed).map(|rel| cursor + rel))
                .unwrap_or(cursor);
            let offset_to = (offset_from + trimmed.len()).min(text.len());
            cursor = offset_to;

            tokens.push(Token {
                offset_from,
                offset_to,
                position,
                text: normalized,
                position_length: 1,
            });
            position += 1;
        }
        VecTokenStream::new(tokens)
    }
}

/// Pure-MIT CJK unigram + adjacent bigram tokenizer over contiguous Han/Kana/Hangul runs.
///
/// - In **index** mode (`for_index()`): emits every CJK unigram AND every adjacent CJK bigram
///   within each contiguous CJK run, guaranteeing 1-char and 2-char ZH/JA/KO literal recall.
/// - In **query** mode (`query_terms()`): emits the unigram for 1-char CJK runs and adjacent
///   bigrams for `>= 2`-char CJK runs so 1-char queries hit unigrams and 2+-char queries match
///   exact bigrams without false positives.
#[derive(Clone, Copy, Debug, Default)]
pub struct CjkBigramTokenizer;

impl CjkBigramTokenizer {
    /// Produce query-side CJK tokens (1-char -> unigram; >=2-char -> adjacent bigrams).
    #[must_use]
    pub fn query_terms(text: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut run: Vec<char> = Vec::new();
        let flush = |run: &mut Vec<char>, out: &mut Vec<String>| {
            if run.len() == 1 {
                if let Some(ch) = run.first() {
                    out.push(ch.to_string());
                }
            } else if run.len() >= 2 {
                for pair in run.windows(2) {
                    let mut gram = String::with_capacity(8);
                    gram.push(pair[0]);
                    gram.push(pair[1]);
                    out.push(gram);
                }
            }
            run.clear();
        };

        for ch in text.chars() {
            if is_cjk_char(ch) {
                run.push(ch);
            } else if !run.is_empty() {
                flush(&mut run, &mut out);
            }
        }
        if !run.is_empty() {
            flush(&mut run, &mut out);
        }
        out
    }
}

impl Tokenizer for CjkBigramTokenizer {
    type TokenStream<'a> = VecTokenStream;

    fn token_stream<'a>(&'a mut self, text: &'a str) -> Self::TokenStream<'a> {
        let mut tokens = Vec::new();
        let mut run: Vec<(usize, usize, char)> = Vec::new();
        let mut position = 0usize;

        let flush_run =
            |run: &mut Vec<(usize, usize, char)>, tokens: &mut Vec<Token>, position: &mut usize| {
                // Emit unigrams for 1-char recall.
                for &(start, end, ch) in run.iter() {
                    tokens.push(Token {
                        offset_from: start,
                        offset_to: end,
                        position: *position,
                        text: ch.to_string(),
                        position_length: 1,
                    });
                    *position += 1;
                }
                // Emit adjacent bigrams for 2+-char recall across ZH/JA/KO.
                for pair in run.windows(2) {
                    let mut gram = String::with_capacity(8);
                    gram.push(pair[0].2);
                    gram.push(pair[1].2);
                    tokens.push(Token {
                        offset_from: pair[0].0,
                        offset_to: pair[1].1,
                        position: *position,
                        text: gram,
                        position_length: 1,
                    });
                    *position += 1;
                }
                run.clear();
            };

        for (byte_idx, ch) in text.char_indices() {
            if is_cjk_char(ch) {
                run.push((byte_idx, byte_idx + ch.len_utf8(), ch));
            } else if !run.is_empty() {
                flush_run(&mut run, &mut tokens, &mut position);
            }
        }
        if !run.is_empty() {
            flush_run(&mut run, &mut tokens, &mut position);
        }
        VecTokenStream::new(tokens)
    }
}

/// Pure-MIT identifier tokenizer preserving whole lowercased non-whitespace tokens
/// (`a+b@example.org`, `inv-2026_01.pdf`, UUIDs) AND emitting delimiter-split sub-tokens
/// (`@ . + - _ / :`).
#[derive(Clone, Copy, Debug, Default)]
pub struct IdentExactTokenizer;

const IDENT_DELIMITERS: &[char] = &['@', '.', '+', '-', '_', '/', ':'];
const WRAPPER_PUNCT: &[char] = &['<', '>', '(', ')', '[', ']', '{', '}', '"', '\'', ',', ';'];

impl IdentExactTokenizer {
    /// Tokenize a query term for exact identifier matching (whole cleaned lowercased token).
    #[must_use]
    pub fn query_exact_terms(text: &str) -> Vec<String> {
        let mut out = Vec::new();
        for piece in text.split_whitespace() {
            let cleaned = clean_ident_token(piece);
            if !cleaned.is_empty() {
                out.push(cleaned);
            }
        }
        out
    }
}

fn clean_ident_token(raw: &str) -> String {
    let trimmed = raw.trim_matches(WRAPPER_PUNCT);
    let normalized: String = trimmed.chars().map(normalize_char).collect();
    let lowered = normalized.to_lowercase();
    if !lowered
        .chars()
        .any(|c| c.is_alphanumeric() || is_cjk_char(c))
    {
        return String::new();
    }
    lowered
}

impl Tokenizer for IdentExactTokenizer {
    type TokenStream<'a> = VecTokenStream;

    fn token_stream<'a>(&'a mut self, text: &'a str) -> Self::TokenStream<'a> {
        let mut tokens = Vec::new();
        let mut position = 0usize;
        let mut search_from = 0usize;

        for raw_piece in text.split_whitespace() {
            let offset_from = text
                .get(search_from..)
                .and_then(|rest| rest.find(raw_piece).map(|rel| search_from + rel))
                .unwrap_or(search_from);
            let offset_to = (offset_from + raw_piece.len()).min(text.len());
            search_from = offset_to;

            let whole = clean_ident_token(raw_piece);
            if whole.is_empty() {
                continue;
            }
            tokens.push(Token {
                offset_from,
                offset_to,
                position,
                text: whole.clone(),
                position_length: 1,
            });
            position += 1;

            // Emit delimiter-split sub-tokens when delimiters are present.
            if whole.contains(IDENT_DELIMITERS) {
                for sub in whole.split(IDENT_DELIMITERS) {
                    if !sub.is_empty() && sub != whole {
                        tokens.push(Token {
                            offset_from,
                            offset_to,
                            position,
                            text: sub.to_owned(),
                            position_length: 1,
                        });
                        position += 1;
                    }
                }
            }
        }

        VecTokenStream::new(tokens)
    }
}

/// Register all Setjoin pure-MIT tokenizers on a Tantivy [`tantivy::Index`].
pub fn register_tokenizers(index: &tantivy::Index, external_dict_path: Option<std::path::PathBuf>) {
    let mgr = index.tokenizers();
    mgr.register(
        ZH_JIEBA_TOKENIZER,
        ZhJiebaTokenizer::new(external_dict_path),
    );
    mgr.register(CJK_BIGRAM_TOKENIZER, CjkBigramTokenizer);
    mgr.register(IDENT_EXACT_TOKENIZER, IdentExactTokenizer);
}
