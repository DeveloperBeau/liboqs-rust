use crate::Declaration;
use crate::DeclarationKind;
use crate::RustToken;
use crate::RustTokenKind;
use crate::RustTokenizer;
use crate::TokenTree;

/// Finds the names that a Rust source file declares.
///
/// The scanner reads token trees, not a syntax tree. Each keyword handler reads the names after
/// its keyword and returns the index of the first tree that it did not use. The main loop then
/// goes into every group that a handler left, so a declaration inside a block is found too.
/// Two groups are never entered: the body of a `macro_rules!` macro, which holds patterns and
/// not declarations, and an `extern` block, whose names the foreign ABI fixes.
pub struct DeclarationScanner {
    declarations: Vec<Declaration>,
}

impl DeclarationScanner {
    /// Returns every declared name in a Rust source text, in source order.
    pub fn declarations(source: &str) -> Vec<Declaration> {
        let trees = TokenTree::trees(RustTokenizer::tokens(source));
        let mut scanner = DeclarationScanner {
            declarations: Vec::new(),
        };
        scanner.scanSequence(&trees);
        scanner.declarations
    }

    fn scanSequence(&mut self, trees: &[TokenTree]) {
        let mut index = 0;
        while index < trees.len() {
            let next = self.scanItem(trees, index);
            // Each handler uses at least one tree, so the loop always ends.
            debug_assert!(next > index, "no progress at tree {index}");
            index = next;
        }
    }

    /// Scans the tree at an index and returns the index of the first tree that it did not use.
    fn scanItem(&mut self, trees: &[TokenTree], index: usize) -> usize {
        let keyword = match trees[index].token() {
            Some(token) if token.kind == RustTokenKind::identifier => token.text.as_str(),
            _ => "",
        };
        match keyword {
            "extern" => Self::skipExtern(trees, index),
            "fn" => self.scanFunction(trees, index),
            "let" | "for" => self.scanBinding(trees, index),
            "const" | "static" => self.scanConstant(trees, index),
            "struct" | "union" => self.scanStructure(trees, index),
            "enum" => self.scanEnumeration(trees, index),
            "trait" => self.scanNamedItem(trees, index, DeclarationKind::protocol),
            "type" => self.scanNamedItem(trees, index, DeclarationKind::r#type),
            "mod" => self.scanNamedItem(trees, index, DeclarationKind::module),
            "macro_rules" => self.scanMacro(trees, index),
            "impl" => self.scanGenerics(trees, index + 1),
            _ => {
                if let TokenTree::group { children, .. } = &trees[index] {
                    self.scanSequence(children);
                }
                index + 1
            }
        }
    }

    fn scanFunction(&mut self, trees: &[TokenTree], index: usize) -> usize {
        // Without a name, `fn` starts a function pointer type such as `fn(u8) -> u8`.
        let Some(name) = Self::nameAt(trees, index + 1) else {
            return index + 1;
        };
        self.record(name, DeclarationKind::function);
        let next = self.scanGenerics(trees, index + 2);
        if let Some(parameters) = trees.get(next).and_then(|tree| tree.children("(")) {
            self.scanNamedFields(parameters, DeclarationKind::parameter);
        }
        next
    }

    /// Scans the pattern after `let` or `for`.
    fn scanBinding(&mut self, trees: &[TokenTree], index: usize) -> usize {
        self.scanPattern(&trees[index + 1..]);
        index + 1
    }

    /// Records the names that a pattern binds: a plain name, or the names in a tuple pattern.
    ///
    /// A name followed by a group, such as `Some(value)`, is a pattern of a type and binds
    /// names that the scanner does not read.
    fn scanPattern(&mut self, trees: &[TokenTree]) {
        let pattern = Self::withoutPrefix(trees);
        let Some(first) = pattern.first() else {
            return;
        };
        if let Some(elements) = first.children("(") {
            for element in TokenTree::commaSeparatedItems(elements) {
                self.scanPattern(element);
            }
        } else if let Some(name) = first.name() {
            let isBinding = pattern.get(1).is_none_or(|next| {
                next.isPunctuation(":")
                    || next.isPunctuation("=")
                    || next.isPunctuation(";")
                    || next.isWord("in")
            });
            if isBinding {
                self.record(name, DeclarationKind::variable);
            }
        }
    }

    fn scanConstant(&mut self, trees: &[TokenTree], index: usize) -> usize {
        // `const fn`, a `const` block and the pointer type `*const u8` have no `name:` after
        // the keyword, so they record nothing.
        if let [nameTree, colon, ..] = Self::withoutPrefix(&trees[index + 1..])
            && colon.isPunctuation(":")
            && let Some(name) = nameTree.name()
        {
            self.record(name, DeclarationKind::constant);
        }
        index + 1
    }

    fn scanStructure(&mut self, trees: &[TokenTree], index: usize) -> usize {
        let Some(name) = Self::nameAt(trees, index + 1) else {
            return index + 1;
        };
        // `union` is a keyword only before a name and a body or a generic list, so a call such
        // as `first.union(&second)` or a name `union` is not a declaration.
        let hasBodyOrGenerics = trees
            .get(index + 2)
            .is_some_and(|tree| tree.children("{").is_some() || tree.isPunctuation("<"));
        if trees[index].isWord("union") && !hasBodyOrGenerics {
            return index + 1;
        }
        self.record(name, DeclarationKind::r#type);
        let next = self.scanGenerics(trees, index + 2);
        // The fields are in the first `{` group before a `;`. A tuple structure has none.
        let fields = trees
            .get(next..)
            .unwrap_or_default()
            .iter()
            .take_while(|tree| !tree.isPunctuation(";"))
            .find_map(|tree| tree.children("{"));
        if let Some(fields) = fields {
            self.scanNamedFields(fields, DeclarationKind::field);
        }
        next
    }

    fn scanEnumeration(&mut self, trees: &[TokenTree], index: usize) -> usize {
        let Some(name) = Self::nameAt(trees, index + 1) else {
            return index + 1;
        };
        self.record(name, DeclarationKind::r#type);
        let next = self.scanGenerics(trees, index + 2);
        let body = trees
            .get(next..)
            .unwrap_or_default()
            .iter()
            .find_map(|tree| tree.children("{"));
        // A discriminant such as `= 1 << 2` holds `<`, so the cases split at every comma, not
        // with the angle bracket count of `commaSeparatedItems`.
        for case in body
            .unwrap_or_default()
            .split(|tree| tree.isPunctuation(","))
        {
            let case = Self::withoutPrefix(case);
            if let Some(caseName) = case.first().and_then(TokenTree::name) {
                self.record(caseName, DeclarationKind::enumerationCase);
            }
            if let Some(fields) = case.get(1).and_then(|tree| tree.children("{")) {
                self.scanNamedFields(fields, DeclarationKind::field);
            }
        }
        next
    }

    fn scanNamedItem(&mut self, trees: &[TokenTree], index: usize, kind: DeclarationKind) -> usize {
        let Some(name) = Self::nameAt(trees, index + 1) else {
            return index + 1;
        };
        self.record(name, kind);
        self.scanGenerics(trees, index + 2)
    }

    fn scanMacro(&mut self, trees: &[TokenTree], index: usize) -> usize {
        let isDefinition = trees
            .get(index + 1)
            .is_some_and(|tree| tree.isPunctuation("!"));
        let Some(name) = Self::nameAt(trees, index + 2).filter(|_| isDefinition) else {
            return index + 1;
        };
        self.record(name, DeclarationKind::r#macro);
        // Step over the keyword, the `!`, the name and the body.
        index + 4
    }

    /// Steps over `extern`, its ABI string and the tree after them.
    ///
    /// That tree is an `extern` block, which the scan must not enter, or the `fn` of a foreign
    /// function, whose name the main loop then sees as a plain name and does not record. In
    /// `extern crate` it is the word `crate`, which has no handler.
    fn skipExtern(trees: &[TokenTree], index: usize) -> usize {
        let hasABI = trees
            .get(index + 1)
            .and_then(TokenTree::token)
            .is_some_and(|token| token.kind == RustTokenKind::literal);
        if hasABI { index + 3 } else { index + 2 }
    }

    /// Records the generic parameters of a `<...>` list that starts at an index, and returns the
    /// index after its closing `>`. Without a list it returns the index unchanged.
    fn scanGenerics(&mut self, trees: &[TokenTree], start: usize) -> usize {
        if !trees.get(start).is_some_and(|tree| tree.isPunctuation("<")) {
            return start;
        }
        let mut depth = 0;
        let mut isParameterStart = false;
        for (offset, tree) in trees[start..].iter().enumerate() {
            if tree.isPunctuation("<") {
                depth += 1;
                isParameterStart = depth == 1;
            } else if tree.isPunctuation(">") {
                depth -= 1;
                if depth == 0 {
                    return start + offset + 1;
                }
            } else if depth == 1 && tree.isPunctuation(",") {
                isParameterStart = true;
            } else if depth == 1 && isParameterStart {
                if let Some(name) = tree.name() {
                    self.record(name, DeclarationKind::genericParameter);
                }
                // After `const` the next tree is the name of the generic constant.
                isParameterStart = tree.isWord("const");
            }
        }
        trees.len()
    }

    /// Records each `name:` that starts an item of a comma-separated list of parameters or
    /// fields.
    fn scanNamedFields(&mut self, trees: &[TokenTree], kind: DeclarationKind) {
        for item in TokenTree::commaSeparatedItems(trees) {
            if let [nameTree, colon, ..] = Self::withoutPrefix(item)
                && colon.isPunctuation(":")
                && let Some(name) = nameTree.name()
            {
                self.record(name, kind);
            }
        }
    }

    /// Removes the attributes, the visibility and the `mut` or `ref` marks at the start of an
    /// item.
    fn withoutPrefix(item: &[TokenTree]) -> &[TokenTree] {
        match item {
            // A `#` at the start of an item always starts an attribute, `#[...]`.
            [hash, _, rest @ ..] if hash.isPunctuation("#") => Self::withoutPrefix(rest),
            [visibility, scope, rest @ ..]
                if visibility.isWord("pub") && scope.children("(").is_some() =>
            {
                Self::withoutPrefix(rest)
            }
            [mark, rest @ ..] if mark.isWord("pub") || mark.isWord("mut") || mark.isWord("ref") => {
                Self::withoutPrefix(rest)
            }
            _ => item,
        }
    }

    fn nameAt(trees: &[TokenTree], index: usize) -> Option<&RustToken> {
        trees.get(index).and_then(TokenTree::name)
    }

    fn record(&mut self, token: &RustToken, kind: DeclarationKind) {
        self.declarations.push(Declaration {
            name: token.text.clone(),
            kind,
            line: token.line,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::DeclarationScanner;
    use crate::DeclarationKind::{self, *};
    use crate::SeededGenerator;

    fn found(source: &str) -> Vec<(String, DeclarationKind)> {
        DeclarationScanner::declarations(source)
            .into_iter()
            .map(|declaration| (declaration.name, declaration.kind))
            .collect()
    }

    fn expected(entries: &[(&str, DeclarationKind)]) -> Vec<(String, DeclarationKind)> {
        entries
            .iter()
            .map(|(name, kind)| (name.to_string(), *kind))
            .collect()
    }

    #[test]
    fn functionWithGenericsAndParametersIsFound() {
        let source = "pub fn generateKeyPair<Random: Rng<u8>, 'a, const Size: usize>(#[allow(x)] random: &'a mut Random, mut seedValue: [u8; Size], (a, b): (u8, u8)) -> u8 { 0 }";
        assert_eq!(
            found(source),
            expected(&[
                ("generateKeyPair", function),
                ("Random", genericParameter),
                ("Size", genericParameter),
                ("random", parameter),
                ("seedValue", parameter),
            ])
        );
    }

    #[test]
    fn functionsAfterOtherItemsKeepTheirParameters() {
        let source = "struct A;\nfn first() {}\npub(crate) fn second<T>(value: T) {}";
        assert_eq!(
            found(source),
            expected(&[
                ("A", r#type),
                ("first", function),
                ("second", function),
                ("T", genericParameter),
                ("value", parameter),
            ])
        );
    }

    #[test]
    fn methodReceiverIsNotAParameter() {
        assert_eq!(
            found("impl A { fn size(&self, extra: u8) {} fn take(self: Box<Self>) {} }"),
            expected(&[("size", function), ("extra", parameter), ("take", function)])
        );
    }

    #[test]
    fn letForAndTuplePatternsAreFound() {
        let source = "fn f() { let a = 1; let mut b: u8 = 2; let c; let (d, (mut e, ref g)) = x; for h in 0..3 {} for (i, j) in y {} let Some(k) = z else { return }; let Point { l, m } = n; }";
        assert_eq!(
            found(source),
            expected(&[
                ("f", function),
                ("a", variable),
                ("b", variable),
                ("c", variable),
                ("d", variable),
                ("e", variable),
                ("g", variable),
                ("h", variable),
                ("i", variable),
                ("j", variable),
            ])
        );
    }

    #[test]
    fn traitImplementationForATypeIsNotALoop() {
        assert_eq!(
            found(
                "impl Display for PublicKey { fn fmt(&self) {} }\nfn g<F>() where F: for<'a> Fn(&'a u8) {}"
            ),
            expected(&[("fmt", function), ("g", function), ("F", genericParameter)])
        );
    }

    #[test]
    fn constantsAndStaticsAreFoundButPointersAndConstFunctionsAreNot() {
        let source = "const maxSize: usize = 1;\nstatic mut counter: u8 = 0;\nconst fn make() {}\nfn g(p: *const u8, q: *mut u8) {}\nconst _: () = ();\nfn h() { const { 1 }; }";
        assert_eq!(
            found(source),
            expected(&[
                ("maxSize", constant),
                ("counter", constant),
                ("make", function),
                ("g", function),
                ("p", parameter),
                ("q", parameter),
                ("h", function),
            ])
        );
    }

    #[test]
    fn declarationsInsideBlocksAndGroupsAreFound() {
        let source =
            "fn outer() { struct Inner { size: [u8; { const Length: usize = 2; Length }] } }";
        assert_eq!(
            found(source),
            expected(&[
                ("outer", function),
                ("Inner", r#type),
                ("size", field),
                ("Length", constant),
            ])
        );
    }

    #[test]
    fn structureFieldsWithVisibilityAndAttributesAreFound() {
        let source = "#[derive(Debug)]\npub struct PublicKey<T> where T: Copy { #[doc = \"x\"] pub(crate) keyBytes: Vec<u8>, pub lengths: HashMap<u8, u8>, other: T, }\nstruct Unit;\nstruct Pair(u8, u8);\nstruct After { last: u8 }";
        assert_eq!(
            found(source),
            expected(&[
                ("PublicKey", r#type),
                ("T", genericParameter),
                ("keyBytes", field),
                ("lengths", field),
                ("other", field),
                ("Unit", r#type),
                ("Pair", r#type),
                ("After", r#type),
                ("last", field),
            ])
        );
    }

    #[test]
    fn tupleStructureBeforeABlockTakesNoFieldsFromIt() {
        assert_eq!(
            found("struct Pair(u8);\nimpl Pair { const notAField: u8 = 1; }"),
            expected(&[("Pair", r#type), ("notAField", constant)])
        );
    }

    #[test]
    fn unionIsADeclarationOnlyBeforeANameAndABody() {
        assert_eq!(
            found(
                "union Bits { whole: u32 }\nunion Wide<T> { part: T }\nfn f() { let all = first.union(&second); }\nexample!(union lowercase);"
            ),
            expected(&[
                ("Bits", r#type),
                ("whole", field),
                ("Wide", r#type),
                ("T", genericParameter),
                ("part", field),
                ("f", function),
                ("all", variable),
            ])
        );
    }

    #[test]
    fn enumerationCasesAndCaseFieldsAreFound() {
        let source = "enum OQSError { #[allow(x)] invalidLength, wrongKey(u8), bad { position: usize }, shifted = 1 << 2, last = 4, }";
        assert_eq!(
            found(source),
            expected(&[
                ("OQSError", r#type),
                ("invalidLength", enumerationCase),
                ("wrongKey", enumerationCase),
                ("bad", enumerationCase),
                ("position", field),
                ("shifted", enumerationCase),
                ("last", enumerationCase),
            ])
        );
    }

    #[test]
    fn genericEnumerationKeepsItsCases() {
        assert_eq!(
            found("pub enum Outcome<Value> where Value: Copy { success(Value), failure }"),
            expected(&[
                ("Outcome", r#type),
                ("Value", genericParameter),
                ("success", enumerationCase),
                ("failure", enumerationCase),
            ])
        );
    }

    #[test]
    fn traitsAliasesModulesAndMacrosAreFound() {
        let source = "pub trait KeyEncapsulating<Key> { type Output; }\ntype Bytes<T> = Vec<T>;\nmod MLKEM768;\nmacro_rules! makeTest { ($name:ident) => { fn $name() {} }; }";
        assert_eq!(
            found(source),
            expected(&[
                ("KeyEncapsulating", protocol),
                ("Key", genericParameter),
                ("Output", r#type),
                ("Bytes", r#type),
                ("T", genericParameter),
                ("MLKEM768", module),
                ("makeTest", r#macro),
            ])
        );
    }

    #[test]
    fn macroBodyIsSteppedOverAndTheScanGoesOnAfterIt() {
        let source = "fn before() {}\nmacro_rules! makeTest { () => { fn hidden_inside() {} } }\nfn after() {}\nmacro_rules ! spaced ( () => {} );\nexample!{ fn insideCall() {} }";
        assert_eq!(
            found(source),
            expected(&[
                ("before", function),
                ("makeTest", r#macro),
                ("after", function),
                ("spaced", r#macro),
                ("insideCall", function),
            ])
        );
    }

    #[test]
    fn macroRulesWithoutABangIsNotADefinition() {
        assert_eq!(
            found("let x = macro_rules; let macro_rules = 1;"),
            expected(&[("x", variable), ("macro_rules", variable)])
        );
    }

    #[test]
    fn commentsStringsCharactersAndLifetimesHideNoNames() {
        let source = "// fn hidden_one() {}\n/* fn hidden_two() { /* nested */ } */\nfn visible<'a>(text: &'a str) -> char { let s = \"fn hidden_three() {}\"; let r = r#\"fn hidden_four\"#; let b = b\"fn x\"; let c = '\\''; let q = '\\\"'; let d = 'x'; 'q' }";
        assert_eq!(
            found(source),
            expected(&[
                ("visible", function),
                ("text", parameter),
                ("s", variable),
                ("r", variable),
                ("b", variable),
                ("c", variable),
                ("q", variable),
                ("d", variable),
            ])
        );
    }

    #[test]
    fn rawIdentifierIsFoundWithoutItsPrefixAndIsNeverAKeyword() {
        assert_eq!(
            found("fn r#match(r#type: u8) {}\nexample!(r#struct Hidden {});\nlet r#fn = 1;"),
            expected(&[("match", function), ("type", parameter), ("fn", variable)])
        );
    }

    #[test]
    fn externBlockAndExternFunctionNamesAreLeftOut() {
        let source = "fn a() {}\nfn b() {}\nunsafe extern \"C\" { fn OQS_KEM_new(name: *const u8) -> *mut u8; static OQS_VERSION: u8; }\npub extern \"C\" fn exported_name() {}\nextern { fn no_abi_name(); }\nextern crate alloc;\nfn after() {}";
        assert_eq!(
            found(source),
            expected(&[("a", function), ("b", function), ("after", function)])
        );
    }

    #[test]
    fn functionPointerTypeIsNotADeclaration() {
        assert_eq!(
            found("fn apply(callback: fn(u8) -> u8) {}"),
            expected(&[("apply", function), ("callback", parameter)])
        );
    }

    #[test]
    fn implGenericsAreGenericParameters() {
        assert_eq!(
            found("impl<T, const Size: usize> Buffer<T, Size> {}\nimpl Plain {}"),
            expected(&[("T", genericParameter), ("Size", genericParameter)])
        );
    }

    #[test]
    fn linesAreTheLinesOfTheNames() {
        let source = "/* one\ntwo */\nlet a = \"x\ny\";\nfn b() {}";
        let lines: Vec<usize> = DeclarationScanner::declarations(source)
            .into_iter()
            .map(|declaration| declaration.line)
            .collect();
        assert_eq!(lines, vec![3, 5]);
    }

    #[test]
    fn keywordsAtTheEndOfTheInputRecordNothing() {
        for source in [
            "fn",
            "let",
            "const",
            "static",
            "struct",
            "union",
            "enum",
            "trait",
            "type",
            "mod",
            "macro_rules",
            "macro_rules !",
            "impl",
            "extern",
            "extern \"C\"",
            "for",
            "fn a<",
            "struct A<T",
        ] {
            let declarations = DeclarationScanner::declarations(source);
            assert!(
                declarations
                    .iter()
                    .all(|declaration| declaration.name != "fn"),
                "{source}"
            );
        }
        assert_eq!(
            found("struct A<T"),
            expected(&[("A", r#type), ("T", genericParameter)])
        );
    }

    /// Random text from Rust fragments must never panic or hang. The seed is printed.
    #[test]
    fn randomFragmentsNeverPanic() {
        let fragments = [
            "fn ",
            "let ",
            "mut ",
            "struct ",
            "union ",
            "enum ",
            "const ",
            "static ",
            "for ",
            "in ",
            "impl",
            "trait ",
            "type ",
            "mod ",
            "<",
            ">",
            "(",
            ")",
            "{",
            "}",
            "[",
            "]",
            ",",
            ";",
            ":",
            "->",
            "'a",
            "'x'",
            "\"s\"",
            "r#\"t\"#",
            "name",
            "Type",
            "#",
            "!",
            "extern ",
            "\"C\" ",
            "macro_rules",
            "/*",
            "*/",
            "//",
            "\n",
            "*",
            "=",
            "pub ",
            "_",
        ];
        let mut generator = SeededGenerator::new(0x53_43_41_4E);
        for _ in 0..3000 {
            let count = generator.nextIndex(40);
            let source: String = (0..count).map(|_| *generator.element(&fragments)).collect();
            let _ = DeclarationScanner::declarations(&source);
        }
    }
}
