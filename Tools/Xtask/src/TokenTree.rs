use crate::RustToken;

/// A token, or a pair of brackets with the token trees between them.
///
/// Brackets are `(`, `[` and `{`. A closing bracket closes the innermost open group, whatever
/// its bracket kind. A closing bracket with no open group is dropped, and a group that is still
/// open at the end of the input closes there. So the trees of broken source still end.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TokenTree {
    /// One token that is not a bracket.
    leaf(RustToken),
    /// An opening bracket and the trees up to its closing bracket.
    group {
        /// The opening bracket.
        open: RustToken,
        /// The trees between the brackets.
        children: Vec<TokenTree>,
    },
}

impl TokenTree {
    /// Returns the trees of a token list, in source order.
    pub fn trees(tokens: Vec<RustToken>) -> Vec<TokenTree> {
        let mut parents: Vec<(RustToken, Vec<TokenTree>)> = Vec::new();
        let mut current = Vec::new();
        for token in tokens {
            if ["(", "[", "{"]
                .iter()
                .any(|bracket| token.isPunctuation(bracket))
            {
                parents.push((token, std::mem::take(&mut current)));
            } else if [")", "]", "}"]
                .iter()
                .any(|bracket| token.isPunctuation(bracket))
            {
                if let Some(parent) = parents.pop() {
                    Self::closeGroup(parent, &mut current);
                }
            } else {
                current.push(TokenTree::leaf(token));
            }
        }
        while let Some(parent) = parents.pop() {
            Self::closeGroup(parent, &mut current);
        }
        current
    }

    /// Splits a tree list at each comma that is not inside angle brackets.
    ///
    /// Angle brackets are tokens, not groups, so `HashMap<K, V>` needs the depth count. An
    /// empty item, such as the one after a trailing comma, is left out.
    pub fn commaSeparatedItems(trees: &[TokenTree]) -> Vec<&[TokenTree]> {
        let mut items = Vec::new();
        let mut depth = 0;
        let mut start = 0;
        for (index, tree) in trees.iter().enumerate() {
            if tree.isPunctuation("<") {
                depth += 1;
            } else if tree.isPunctuation(">") {
                depth -= 1;
            } else if depth == 0 && tree.isPunctuation(",") {
                items.push(&trees[start..index]);
                start = index + 1;
            }
        }
        items.push(&trees[start..]);
        items.retain(|item| !item.is_empty());
        items
    }

    /// The token, when the tree is a leaf.
    pub fn token(&self) -> Option<&RustToken> {
        match self {
            TokenTree::leaf(token) => Some(token),
            TokenTree::group { .. } => None,
        }
    }

    /// The token, when the tree is a leaf that can be a declared name.
    pub fn name(&self) -> Option<&RustToken> {
        self.token().filter(|token| token.isName())
    }

    /// The trees inside the group, when the tree is a group that opens with a bracket.
    pub fn children(&self, bracket: &str) -> Option<&[TokenTree]> {
        match self {
            TokenTree::group { open, children } if open.text == bracket => Some(children),
            _ => None,
        }
    }

    /// True when the tree is a leaf with the identifier or keyword `word`.
    pub fn isWord(&self, word: &str) -> bool {
        self.token().is_some_and(|token| token.isWord(word))
    }

    /// True when the tree is a leaf with the punctuation `text`.
    pub fn isPunctuation(&self, text: &str) -> bool {
        self.token().is_some_and(|token| token.isPunctuation(text))
    }

    fn closeGroup(parent: (RustToken, Vec<TokenTree>), current: &mut Vec<TokenTree>) {
        let (open, siblings) = parent;
        let children = std::mem::replace(current, siblings);
        current.push(TokenTree::group { open, children });
    }
}

#[cfg(test)]
mod tests {
    use super::TokenTree;
    use crate::RustTokenizer;

    /// Writes trees back as text, with each group in its own brackets, so a test can compare
    /// the shape with a hand-written string.
    fn shape(trees: &[TokenTree]) -> String {
        trees
            .iter()
            .map(|tree| match tree {
                TokenTree::leaf(token) => token.text.clone(),
                TokenTree::group { open, children } => {
                    let close = match open.text.as_str() {
                        "(" => ")",
                        "[" => "]",
                        _ => "}",
                    };
                    format!("{}{}{}", open.text, shape(children), close)
                }
            })
            .collect::<Vec<String>>()
            .join(" ")
    }

    fn trees(source: &str) -> Vec<TokenTree> {
        TokenTree::trees(RustTokenizer::tokens(source))
    }

    #[test]
    fn bracketsBecomeNestedGroups() {
        assert_eq!(shape(&trees("a(b[c]{d})e")), "a (b [c] {d}) e");
    }

    #[test]
    fn closingBracketClosesTheInnermostGroupOfAnyKind() {
        assert_eq!(shape(&trees("a(b]c")), "a (b) c");
    }

    #[test]
    fn strayClosingBracketIsDroppedAndOpenGroupsCloseAtTheEnd() {
        assert_eq!(shape(&trees("a)b")), "a b");
        assert_eq!(shape(&trees("a{b(c")), "a {b (c)}");
    }

    #[test]
    fn bracketsInsideLiteralsAndCommentsMakeNoGroup() {
        assert_eq!(shape(&trees("a \"(\" '{' /* [ */ b")), "a \"(\" '{' b");
    }

    #[test]
    fn commaSeparatedItemsSplitOnlyOutsideAngleBrackets() {
        let list = trees("a: HashMap<K, V>, b: Vec<Vec<u8>>, c: (u8, u8),");
        let items: Vec<String> = TokenTree::commaSeparatedItems(&list)
            .into_iter()
            .map(shape)
            .collect();
        assert_eq!(
            items,
            vec![
                "a : HashMap < K , V >",
                "b : Vec < Vec < u8 > >",
                "c : (u8 , u8)"
            ]
        );
    }

    #[test]
    fn commaSeparatedItemsLeaveOutEmptyItems() {
        let list = trees(",a,,b,");
        let items: Vec<String> = TokenTree::commaSeparatedItems(&list)
            .into_iter()
            .map(shape)
            .collect();
        assert_eq!(items, vec!["a", "b"]);
        assert!(TokenTree::commaSeparatedItems(&[]).is_empty());
    }

    #[test]
    fn accessorsTellLeavesAndGroupsApart() {
        let list = trees("name fn ( x ) [ y ] ,");
        assert_eq!(
            list[0].name().map(|token| token.text.as_str()),
            Some("name")
        );
        assert!(list[1].name().is_none());
        assert!(list[1].isWord("fn"));
        assert!(!list[0].isWord("fn"));
        assert_eq!(list[2].children("(").map(shape), Some("x".to_string()));
        assert!(list[2].children("[").is_none());
        assert!(list[2].token().is_none());
        assert!(!list[2].isWord("x"));
        assert!(list[3].children("[").is_some());
        assert!(list[4].isPunctuation(","));
        assert!(!list[2].isPunctuation(","));
    }
}
