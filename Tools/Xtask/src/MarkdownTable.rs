/// The first table of a Markdown document, as the text of its cells.
#[derive(Debug, PartialEq, Eq)]
pub struct MarkdownTable {
    /// The header cells, in column order.
    pub header: Vec<String>,
    /// The body rows. Each row has one cell for each header cell.
    pub rows: Vec<Vec<String>>,
}

impl MarkdownTable {
    /// Reads the first table in a Markdown document, or returns `None` when there is no table.
    ///
    /// A row with fewer cells than the header gets empty cells, so that a column read never
    /// falls off the end of a short row.
    pub fn firstTable(document: &str) -> Option<Self> {
        let mut tableLines = document
            .lines()
            .map(str::trim)
            .skip_while(|line| !line.starts_with('|'))
            .take_while(|line| line.starts_with('|'));
        let header = Self::cells(tableLines.next()?);
        let separator = tableLines.next()?;
        if !separator
            .chars()
            .all(|character| "|-: ".contains(character))
        {
            return None;
        }
        let rows = tableLines
            .map(|line| {
                let mut row = Self::cells(line);
                row.resize(header.len(), String::new());
                row
            })
            .collect();
        Some(MarkdownTable { header, rows })
    }

    /// Returns the cells of the column under a header, one for each row.
    pub fn column(&self, header: &str) -> Option<Vec<&str>> {
        let index = self.header.iter().position(|cell| cell == header)?;
        Some(self.rows.iter().map(|row| row[index].as_str()).collect())
    }

    /// Returns the items of a cell that holds a comma-separated list.
    ///
    /// Code marks are removed. The word `none` stands for an empty list.
    pub fn listItems(cell: &str) -> Vec<String> {
        cell.split(',')
            .map(|item| item.trim().trim_matches('`').trim().to_string())
            .filter(|item| !item.is_empty() && item != "none")
            .collect()
    }

    fn cells(line: &str) -> Vec<String> {
        let inner = line.trim().trim_start_matches('|').trim_end_matches('|');
        inner
            .split('|')
            .map(|cell| cell.trim().to_string())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::MarkdownTable;

    const document: &str = "# Title\n\nText.\n\n| Ring | May depend on |\n|---|---|\n| `domain` | `entities` |\n| entities | none |\n\n| Other | Table |\n|---|---|\n| a | b |\n";

    #[test]
    fn firstTableReadsHeaderAndRowsOfTheFirstTableOnly() {
        let table = MarkdownTable::firstTable(document).expect("table");
        assert_eq!(table.header, vec!["Ring", "May depend on"]);
        assert_eq!(
            table.rows,
            vec![vec!["`domain`", "`entities`"], vec!["entities", "none"]]
        );
    }

    #[test]
    fn firstTableIsNoneWhenTheDocumentHasNoTable() {
        assert_eq!(MarkdownTable::firstTable("# Title\n\nNo table.\n"), None);
    }

    #[test]
    fn firstTableIsNoneWhenTheSecondLineIsNotASeparator() {
        assert_eq!(MarkdownTable::firstTable("| a | b |\n| c | d |\n"), None);
    }

    #[test]
    fn firstTablePadsAShortRowWithEmptyCells() {
        let table = MarkdownTable::firstTable("| a | b |\n|---|---|\n| c |\n").expect("table");
        assert_eq!(table.rows, vec![vec!["c", ""]]);
    }

    #[test]
    fn columnReturnsTheCellsUnderAHeader() {
        let table = MarkdownTable::firstTable(document).expect("table");
        assert_eq!(table.column("Ring"), Some(vec!["`domain`", "entities"]));
        assert_eq!(table.column("Missing"), None);
    }

    #[test]
    fn listItemsRemovesCodeMarksAndReadsNoneAsEmpty() {
        assert_eq!(
            MarkdownTable::listItems("`entities`, domain ,"),
            vec!["entities", "domain"]
        );
        assert!(MarkdownTable::listItems("none").is_empty());
        assert!(MarkdownTable::listItems("").is_empty());
    }
}
