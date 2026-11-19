//! Validation algebra for composing PSBT rules as a declarative tree.
//!
//! A node either validates the current context (`Rule`), runs children in
//! sequence (`All`), projects the context (`With`), iterates it (`Each`), or
//! gates a subtree on a predicate (`When`) or on a BIP the validator implements
//! (`From`). spec.rs builds the specification from these nodes.

/// A rule violation. `rule` is the failing rule's ID, which is also its unique
/// error code: base validation succeeds if no applicable validity rule fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub rule: &'static str,
    pub detail: String,
}

pub type Verdict = Result<(), Violation>;

/// The leaf validator signature, defaulting to a binary check with error detail.
pub type Check<C, R = Result<(), String>> = fn(&C) -> R;

/// The outcome of a leaf check before attaching its rule ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckOutcome {
    Verified,
    NotApplicable,
    Incomplete(String),
    Failed(String),
}

impl From<Result<(), String>> for CheckOutcome {
    fn from(result: Result<(), String>) -> Self {
        match result {
            Ok(()) => Self::Verified,
            Err(detail) => Self::Failed(detail),
        }
    }
}

/// Evaluation distinguishes skipped rules from verified rules and incomplete checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Evaluation {
    Verified,
    NotApplicable,
    Incomplete(Violation),
    Failed(Violation),
}

impl Evaluation {
    /// Preserves the legacy verdict API without treating incomplete checks as success.
    pub fn into_verdict(self) -> Verdict {
        match self {
            Self::Verified | Self::NotApplicable => Ok(()),
            Self::Incomplete(violation) | Self::Failed(violation) => Err(violation),
        }
    }
}

/// BIPs that may extend the base rules. A validator enables the ones it implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bip {
    Bip372,
    Bip375,
    Bip376,
}

impl Bip {
    pub fn name(self) -> &'static str {
        match self {
            Bip::Bip372 => "BIP-372",
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
        /// The enclosing role phase, Precondition or Result; None for a General rule.
        phase: Option<&'static str>,
    },
}

#[derive(Default)]
pub struct Doc {
    pub entries: Vec<Entry>,
    gates: Vec<String>,
    phase: Option<&'static str>,
}

/// An observation of one rule, including rules skipped by graph control flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleObservation {
    pub id: &'static str,
    pub status: TraceStatus,
    pub detail: String,
    /// Zero-based indices of enclosing Each iterations, outermost first.
    pub path: Vec<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceStatus {
    Passed,
    Failed,
    Incomplete,
    NotApplicable,
    Gated,
    Blocked,
    Empty,
}

/// Records graph execution without bypassing prerequisites or changing outcomes.
#[derive(Debug, Default)]
pub struct Trace {
    pub observations: Vec<RuleObservation>,
    path: Vec<usize>,
    exhaustive: bool,
}

impl Trace {
    /// A trace that keeps evaluating after a failure, for coverage reporting.
    /// Sibling rules and later items still run; a later sibling that projects
    /// a new context (`with`) is Blocked, since its projection may rely on what
    /// failed. The returned outcome is the same as without it.
    pub fn exhaustive() -> Self {
        Self { exhaustive: true, ..Self::default() }
    }

    fn record(&mut self, id: &'static str, status: TraceStatus, detail: String) {
        self.observations.push(RuleObservation {
            id, status, detail, path: self.path.clone(),
        });
    }

    fn subtree<C: ?Sized>(&mut self, node: &dyn Node<C>, status: TraceStatus, detail: &str) {
        let mut doc = Doc::default();
        node.describe(&mut doc);
        for entry in doc.entries {
            if let Entry::Rule { id, .. } = entry {
                self.record(id, status, detail.into());
            }
        }
    }
}

fn blocked_reason(outcome: &Evaluation) -> String {
    match outcome {
        Evaluation::Failed(violation) | Evaluation::Incomplete(violation) =>
            format!("Stopped at {}: {}", violation.rule, violation.detail),
        _ => unreachable!("only terminal outcomes block later rules"),
    }
}

pub trait Node<C: ?Sized> {
    fn evaluate(&self, ctx: &C) -> Evaluation;
    /// Built-in nodes record rule observations; custom nodes can override this.
    fn evaluate_traced(&self, ctx: &C, _trace: &mut Trace) -> Evaluation {
        self.evaluate(ctx)
    }
    fn validate(&self, ctx: &C) -> Verdict {
        self.evaluate(ctx).into_verdict()
    }
    fn describe(&self, doc: &mut Doc);
    /// Whether the subtree projects a new context, which an exhaustive trace
    /// must not do after an earlier sibling failed.
    fn projects(&self) -> bool {
        false
    }
}

pub type BoxNode<C> = Box<dyn Node<C>>;

pub struct Rule<C: ?Sized, R = Result<(), String>> {
    pub id: &'static str,
    pub text: &'static str,
    pub func: &'static str,
    pub file: &'static str,
    pub line: u32,
    pub check: Check<C, R>,
}

impl<C: ?Sized, R: Into<CheckOutcome>> Node<C> for Rule<C, R> {
    fn evaluate(&self, ctx: &C) -> Evaluation {
        match (self.check)(ctx).into() {
            CheckOutcome::Verified => Evaluation::Verified,
            CheckOutcome::NotApplicable => Evaluation::NotApplicable,
            CheckOutcome::Incomplete(detail) => Evaluation::Incomplete(Violation { rule: self.id, detail }),
            CheckOutcome::Failed(detail) => Evaluation::Failed(Violation { rule: self.id, detail }),
        }
    }
    fn evaluate_traced(&self, ctx: &C, trace: &mut Trace) -> Evaluation {
        let outcome = self.evaluate(ctx);
        let (status, detail) = match &outcome {
            Evaluation::Verified => (TraceStatus::Passed, String::new()),
            Evaluation::NotApplicable => (TraceStatus::NotApplicable, String::new()),
            Evaluation::Failed(v) => (TraceStatus::Failed, v.detail.clone()),
            Evaluation::Incomplete(v) => (TraceStatus::Incomplete, v.detail.clone()),
        };
        trace.record(self.id, status, detail);
        outcome
    }
    fn describe(&self, doc: &mut Doc) {
        doc.entries.push(Entry::Rule {
            id: self.id,
            text: self.text,
            func: self.func,
            file: self.file,
            line: self.line,
            gates: doc.gates.clone(),
            phase: doc.phase,
        });
    }
}

/// `check!("GEN-F-1", validate_fn)`: binds a check to a rule declared in
/// spec.rs, which supplies the wording.
#[macro_export]
macro_rules! check {
    ($id:literal, $check:path) => {
        $crate::rule!($id, $check, "")
    };
}

/// `rule!("G01", validate_fn, "Normative sentence.")`
#[macro_export]
macro_rules! rule {
    ($id:literal, $check:path, $text:expr) => {
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

/// Runs children in order, stopping at the first incomplete check or failure.
/// No later child is evaluated after an incomplete check, even if it could fail.
/// Runs children in sequence. An exhaustive trace keeps running them after a
/// failure unless the group is ordered (`seq`).
pub struct All<C: ?Sized> {
    children: Vec<BoxNode<C>>,
    ordered: bool,
}

impl<C: ?Sized> Node<C> for All<C> {
    fn evaluate(&self, ctx: &C) -> Evaluation {
        let mut result = Evaluation::NotApplicable;
        for child in &self.children {
            match child.evaluate(ctx) {
                Evaluation::Verified => result = Evaluation::Verified,
                Evaluation::NotApplicable => {},
                other => return other,
            }
        }
        result
    }
    fn evaluate_traced(&self, ctx: &C, trace: &mut Trace) -> Evaluation {
        let mut result = Evaluation::NotApplicable;
        let mut first: Option<Evaluation> = None;
        for (index, child) in self.children.iter().enumerate() {
            if let Some(failed) = &first {
                // Exhaustive: run independent siblings, block projections.
                if child.projects() {
                    trace.subtree(child.as_ref(), TraceStatus::Blocked, &blocked_reason(failed));
                } else {
                    child.evaluate_traced(ctx, trace);
                }
                continue;
            }
            match child.evaluate_traced(ctx, trace) {
                Evaluation::Verified => result = Evaluation::Verified,
                Evaluation::NotApplicable => {},
                outcome if trace.exhaustive && !self.ordered => first = Some(outcome),
                outcome => {
                    let reason = blocked_reason(&outcome);
                    for later in &self.children[index + 1..] {
                        trace.subtree(later.as_ref(), TraceStatus::Blocked, &reason);
                    }
                    return outcome;
                }
            }
        }
        first.unwrap_or(result)
    }
    fn projects(&self) -> bool {
        self.children.iter().any(|child| child.projects())
    }
    fn describe(&self, doc: &mut Doc) {
        self.children.iter().for_each(|child| child.describe(doc));
    }
}

pub fn all<C: ?Sized + 'static>(children: Vec<BoxNode<C>>) -> BoxNode<C> {
    Box::new(All { children, ordered: false })
}

/// Like `all`, but each child may rely on the ones before it, so an exhaustive
/// trace still stops at the first failure.
pub fn seq<C: ?Sized + 'static>(children: Vec<BoxNode<C>>) -> BoxNode<C> {
    Box::new(All { children, ordered: true })
}

/// A titled group of rules. It validates exactly like its child.
pub struct Section<C: ?Sized> {
    title: &'static str,
    child: BoxNode<C>,
}

impl<C: ?Sized> Node<C> for Section<C> {
    fn evaluate(&self, ctx: &C) -> Evaluation {
        self.child.evaluate(ctx)
    }
    fn evaluate_traced(&self, ctx: &C, trace: &mut Trace) -> Evaluation {
        self.child.evaluate_traced(ctx, trace)
    }
    fn describe(&self, doc: &mut Doc) {
        doc.entries.push(Entry::Section(self.title));
        self.child.describe(doc);
    }
    fn projects(&self) -> bool {
        self.child.projects()
    }
}

/// A role's rules checked at one phase. It validates exactly like its child.
pub struct Phase<C: ?Sized> {
    label: &'static str,
    child: BoxNode<C>,
}

impl<C: ?Sized> Node<C> for Phase<C> {
    fn evaluate(&self, ctx: &C) -> Evaluation {
        self.child.evaluate(ctx)
    }
    fn evaluate_traced(&self, ctx: &C, trace: &mut Trace) -> Evaluation {
        self.child.evaluate_traced(ctx, trace)
    }
    fn describe(&self, doc: &mut Doc) {
        let outer = doc.phase.replace(self.label);
        self.child.describe(doc);
        doc.phase = outer;
    }
    fn projects(&self) -> bool {
        self.child.projects()
    }
}

/// Rules checked on the PSBT a role received; failing one means the role must refuse.
pub fn precondition<C: ?Sized + 'static>(child: BoxNode<C>) -> BoxNode<C> {
    Box::new(Phase { label: "Precondition", child })
}

/// Rules checked on the PSBT a role returned, alone or against what it received.
pub fn result<C: ?Sized + 'static>(child: BoxNode<C>) -> BoxNode<C> {
    Box::new(Phase { label: "Result", child })
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
    fn evaluate(&self, ctx: &C) -> Evaluation {
        self.child.evaluate(&(self.project)(ctx))
    }
    fn evaluate_traced(&self, ctx: &C, trace: &mut Trace) -> Evaluation {
        self.child.evaluate_traced(&(self.project)(ctx), trace)
    }
    fn describe(&self, doc: &mut Doc) {
        self.child.describe(doc);
    }
    fn projects(&self) -> bool {
        true
    }
}

pub fn with<C: ?Sized + 'static, D: 'static>(project: impl Fn(&C) -> D + 'static, child: BoxNode<D>) -> BoxNode<C> {
    Box::new(With { project: Box::new(project), child })
}

/// Evaluates elements in enumeration order, stopping at the first incomplete
/// check or failure. No later element is evaluated after an incomplete check.
pub struct Each<C: ?Sized, D> {
    enumerate: fn(&C) -> Vec<D>,
    child: BoxNode<D>,
}

impl<C: ?Sized, D> Node<C> for Each<C, D> {
    fn evaluate(&self, ctx: &C) -> Evaluation {
        let mut result = Evaluation::NotApplicable;
        for item in (self.enumerate)(ctx).iter() {
            match self.child.evaluate(item) {
                Evaluation::Verified => result = Evaluation::Verified,
                Evaluation::NotApplicable => {},
                other => return other,
            }
        }
        result
    }
    fn evaluate_traced(&self, ctx: &C, trace: &mut Trace) -> Evaluation {
        let items = (self.enumerate)(ctx);
        if items.is_empty() {
            trace.subtree(self.child.as_ref(), TraceStatus::Empty, "No items to evaluate");
        }
        let mut result = Evaluation::NotApplicable;
        let mut first: Option<Evaluation> = None;
        for (index, item) in items.iter().enumerate() {
            trace.path.push(index);
            let outcome = self.child.evaluate_traced(item, trace);
            trace.path.pop();
            match outcome {
                Evaluation::Verified => result = Evaluation::Verified,
                Evaluation::NotApplicable => {},
                // Exhaustive: items are independent, so later ones still run.
                outcome if trace.exhaustive => {
                    first.get_or_insert(outcome);
                }
                outcome => {
                    let reason = blocked_reason(&outcome);
                    for later in index + 1..items.len() {
                        trace.path.push(later);
                        trace.subtree(self.child.as_ref(), TraceStatus::Blocked, &reason);
                        trace.path.pop();
                    }
                    return outcome;
                }
            }
        }
        first.unwrap_or(result)
    }
    fn describe(&self, doc: &mut Doc) {
        self.child.describe(doc);
    }
    fn projects(&self) -> bool {
        self.child.projects()
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
    fn evaluate(&self, ctx: &C) -> Evaluation {
        if (self.predicate)(ctx) {
            return self.child.evaluate(ctx);
        }
        Evaluation::NotApplicable
    }
    fn evaluate_traced(&self, ctx: &C, trace: &mut Trace) -> Evaluation {
        if (self.predicate)(ctx) {
            self.child.evaluate_traced(ctx, trace)
        } else {
            trace.subtree(self.child.as_ref(), TraceStatus::Gated,
                &format!("Condition disabled: {}", self.label));
            Evaluation::NotApplicable
        }
    }
    fn describe(&self, doc: &mut Doc) {
        doc.gates.push(self.label.clone());
        self.child.describe(doc);
        doc.gates.pop();
    }
    fn projects(&self) -> bool {
        self.child.projects()
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
