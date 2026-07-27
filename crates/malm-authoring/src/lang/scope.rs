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

    /// Resolves a reference name. Dotted names recursively address record
    /// fields (`entry.options.label`); global and built-in namespaces are
    /// matched verbatim first.
    pub fn lookup(&self, name: &str) -> Option<&Value> {
        if let Some((_, value)) = self.bindings.iter().rev().find(|(n, _)| n == name) {
            return Some(value);
        }
        if let Some((binding, value)) = longest_binding_prefix(&self.bindings, name) {
            return value.get_path(&name[binding.len() + 1..]);
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
        if let Some((input, value)) = self
            .inputs
            .iter()
            .filter(|(input, _)| {
                name.starts_with(input.as_str()) && name.as_bytes().get(input.len()) == Some(&b'.')
            })
            .max_by_key(|(input, _)| input.len())
        {
            return value.get_path(&name[input.len() + 1..]);
        }
        None
    }

    /// Pushes a loop binding after static shadow checks.
    pub fn push_binding(&mut self, name: impl Into<String>, value: Value) {
        self.bindings.push((name.into(), value));
    }

    pub fn pop_binding(&mut self) {
        self.bindings.pop();
    }
}

fn longest_binding_prefix<'a>(
    bindings: &'a [(String, Value)],
    name: &str,
) -> Option<(&'a String, &'a Value)> {
    let mut best: Option<(&String, &Value)> = None;
    for (binding, value) in bindings.iter().rev() {
        if name.starts_with(binding)
            && name.as_bytes().get(binding.len()) == Some(&b'.')
            && best.is_none_or(|(current, _)| binding.len() > current.len())
        {
            best = Some((binding, value));
        }
    }
    best
}
