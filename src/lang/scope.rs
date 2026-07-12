//! Typed inputs, globals, built-ins, and loop bindings for one module instance.

use crate::lang::value::Value;
use std::collections::HashMap;

#[derive(Debug)]
pub struct Scope {
    inputs: HashMap<String, Value>,
    globals: HashMap<String, Value>,
    /// Built-ins: `malm.target`, `profile.name`, `machine.hostname`,
    /// `instance.name`, `instance.module`.
    builtins: HashMap<String, Value>,
    /// Loop bindings, innermost last.
    bindings: Vec<(String, Value)>,
}

impl Scope {
    pub fn new(
        inputs: HashMap<String, Value>,
        globals: HashMap<String, Value>,
        builtins: HashMap<String, Value>,
    ) -> Self {
        Self {
            inputs,
            globals,
            builtins,
            bindings: Vec::new(),
        }
    }

    /// Resolve a reference name. Dotted names address record fields
    /// (`entry.label`); `global.*` and built-in namespaces are matched
    /// verbatim first.
    pub fn lookup(&self, name: &str) -> Option<&Value> {
        if let Some((_, value)) = self.bindings.iter().rev().find(|(n, _)| n == name) {
            return Some(value);
        }
        if let Some((head, field)) = name.split_once('.')
            && let Some((_, Value::Record(record))) =
                self.bindings.iter().rev().find(|(n, _)| n == head)
        {
            return record.get(field);
        }
        if let Some(value) = self.globals.get(name) {
            return Some(value);
        }
        if let Some(value) = self.builtins.get(name) {
            return Some(value);
        }
        if let Some(value) = self.inputs.get(name) {
            return Some(value);
        }
        if let Some((head, field)) = name.split_once('.')
            && let Some(Value::Record(record)) = self.inputs.get(head)
        {
            return record.get(field);
        }
        if let Some((head, _)) = name.split_once('.')
            && self.inputs.get(head).is_some_and(Value::is_null)
        {
            static NULL: Value = Value::Null;
            return Some(&NULL);
        }
        None
    }

    /// Push a loop binding after static shadow checks.
    pub fn push_binding(&mut self, name: impl Into<String>, value: Value) {
        self.bindings.push((name.into(), value));
    }

    pub fn pop_binding(&mut self) {
        self.bindings.pop();
    }
}
