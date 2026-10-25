//! Validation algebra for composing PSBT rules as a declarative tree.
//!
//! A node either validates the current context (`Rule`), runs children in
//! sequence (`All`), projects the context (`With`), iterates it (`Each`), or
//! gates a subtree on a predicate (`When`) or on a BIP the validator implements
//! (`From`). The same tree that validates also describes itself, so the
//! rendered specification cannot drift from the code that enforces it.

/// A rule violation. `rule` is the failing rule's ID, which is also its unique
/// error code: a PSBT is valid if and only if no rule returns a violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub rule: &'static str,
    pub detail: String,
}

pub type Verdict = Result<(), Violation>;

/// The leaf validator signature: `Err` carries a human readable detail.
pub type Check<C> = fn(&C) -> Result<(), String>;

/// BIPs that may extend the base rules. A validator enables the ones it implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bip {
    Bip375,
    Bip376,
}

impl Bip {
    pub fn name(self) -> &'static str {
        match self {
            Bip::Bip375 => "BIP-375",
            Bip::Bip376 => "BIP-376",
        }
    }
}

/// One line of the rendered specification.
#[derive(Debug, Clone)]
pub enum Entry {
    Section(&'static str),
    Rule {
        id: &'static str,
        text: &'static str,
        func: &'static str,
        file: &'static str,
        line: u32,
        /// Conditions inherited from enclosing `When` and `From` nodes.
        gates: Vec<String>,
    },
}

#[derive(Default)]
pub struct Doc {
    pub entries: Vec<Entry>,
    gates: Vec<String>,
}

pub trait Node<C: ?Sized> {
    fn validate(&self, ctx: &C) -> Verdict;
    fn describe(&self, doc: &mut Doc);
}

pub type BoxNode<C> = Box<dyn Node<C>>;

pub struct Rule<C: ?Sized> {
    pub id: &'static str,
    pub text: &'static str,
    pub func: &'static str,
    pub file: &'static str,
    pub line: u32,
    pub check: Check<C>,
}

impl<C: ?Sized> Node<C> for Rule<C> {
    fn validate(&self, ctx: &C) -> Verdict {
        (self.check)(ctx).map_err(|detail| Violation { rule: self.id, detail })
    }
    fn describe(&self, doc: &mut Doc) {
        doc.entries.push(Entry::Rule {
            id: self.id,
            text: self.text,
            func: self.func,
            file: self.file,
            line: self.line,
            gates: doc.gates.clone(),
        });
    }
}

/// `rule!("G01", validate_fn, "Normative sentence.")`
#[macro_export]
macro_rules! rule {
    ($id:literal, $check:path, $text:literal) => {
        Box::new($crate::algebra::Rule {
            id: $id,
            text: $text,
            func: stringify!($check),
            file: file!(),
            line: line!(),
            check: $check,
        })
    };
}

/// Runs each child against the same context in sequence, stopping at the first failure.
pub struct All<C: ?Sized>(pub Vec<BoxNode<C>>);

impl<C: ?Sized> Node<C> for All<C> {
    fn validate(&self, ctx: &C) -> Verdict {
        self.0.iter().try_for_each(|child| child.validate(ctx))
    }
    fn describe(&self, doc: &mut Doc) {
        self.0.iter().for_each(|child| child.describe(doc));
    }
}

pub fn all<C: ?Sized + 'static>(children: Vec<BoxNode<C>>) -> BoxNode<C> {
    Box::new(All(children))
}

/// A titled group of rules. It validates exactly like its child.
pub struct Section<C: ?Sized> {
    title: &'static str,
    child: BoxNode<C>,
}

impl<C: ?Sized> Node<C> for Section<C> {
    fn validate(&self, ctx: &C) -> Verdict {
        self.child.validate(ctx)
    }
    fn describe(&self, doc: &mut Doc) {
        doc.entries.push(Entry::Section(self.title));
        self.child.describe(doc);
    }
}

pub fn section<C: ?Sized + 'static>(title: &'static str, child: BoxNode<C>) -> BoxNode<C> {
    Box::new(Section { title, child })
}

/// Projects the current context into a child context. Projections are
/// infallible: the rules that precede a `With` establish what it relies on.
pub struct With<C: ?Sized, D> {
    project: Box<dyn Fn(&C) -> D>,
    child: BoxNode<D>,
}

impl<C: ?Sized, D> Node<C> for With<C, D> {
    fn validate(&self, ctx: &C) -> Verdict {
        self.child.validate(&(self.project)(ctx))
    }
    fn describe(&self, doc: &mut Doc) {
        self.child.describe(doc);
    }
}

pub fn with<C: ?Sized + 'static, D: 'static>(project: impl Fn(&C) -> D + 'static, child: BoxNode<D>) -> BoxNode<C> {
    Box::new(With { project: Box::new(project), child })
}

/// Validates each element the enumerator yields with the same child node.
pub struct Each<C: ?Sized, D> {
    enumerate: fn(&C) -> Vec<D>,
    child: BoxNode<D>,
}

impl<C: ?Sized, D> Node<C> for Each<C, D> {
    fn validate(&self, ctx: &C) -> Verdict {
        (self.enumerate)(ctx).iter().try_for_each(|item| self.child.validate(item))
    }
    fn describe(&self, doc: &mut Doc) {
        self.child.describe(doc);
    }
}

pub fn each<C: ?Sized + 'static, D: 'static>(enumerate: fn(&C) -> Vec<D>, child: BoxNode<D>) -> BoxNode<C> {
    Box::new(Each { enumerate, child })
}

/// Validates the child only when the predicate holds. `label` names the
/// condition in the rendered specification, such as "PSBTv2".
pub struct When<C: ?Sized> {
    label: String,
    predicate: fn(&C) -> bool,
    child: BoxNode<C>,
}

impl<C: ?Sized> Node<C> for When<C> {
    fn validate(&self, ctx: &C) -> Verdict {
        if (self.predicate)(ctx) {
            return self.child.validate(ctx);
        }
        Ok(())
    }
    fn describe(&self, doc: &mut Doc) {
        doc.gates.push(self.label.clone());
        self.child.describe(doc);
        doc.gates.pop();
    }
}

pub fn when<C: ?Sized + 'static>(label: &str, predicate: fn(&C) -> bool, child: BoxNode<C>) -> BoxNode<C> {
    Box::new(When { label: label.to_string(), predicate, child })
}

/// Gates a subtree on a BIP the validator implements. A validator that does
/// not implement the BIP treats its fields as unknown and skips its rules.
pub fn from<C: ?Sized + 'static>(bip: Bip, enabled: &[Bip], child: BoxNode<C>) -> BoxNode<C> {
    let label = format!("From {}", bip.name());
    if enabled.contains(&bip) {
        when(&label, |_| true, child)
    } else {
        when(&label, |_| false, child)
    }
}
