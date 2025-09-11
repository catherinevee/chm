# anti-CLAUDE.md
## AI Code Assistant Anti-Patterns and Prohibited Behaviors

This document defines coding anti-patterns, shortcuts, and behaviors that AI code assistants MUST avoid when generating or modifying code.

---

## 🚫 Code Generation Anti-Patterns

### 1. Placeholder Code
**NEVER** use placeholder implementations or mock data without explicit request:
- ❌ `// TODO: Implement this later`
- ❌ `console.log("This will do something")`
- ❌ `return "mock-data"`
- ❌ Dummy API endpoints that don't connect to real services
- ✅ Always provide complete, functional implementations

### 2. Incomplete Error Handling
**NEVER** ignore error cases or use generic catch-all handlers:
- ❌ Empty catch blocks: `catch(e) {}`
- ❌ Silent failures without logging
- ❌ Generic error messages: `"An error occurred"`
- ✅ Implement specific error handling with meaningful messages
- ✅ Log errors appropriately for debugging

### 3. Oversimplification
**NEVER** oversimplify complex requirements:
- ❌ Removing validation "for simplicity"
- ❌ Skipping authentication/authorization checks
- ❌ Ignoring edge cases
- ❌ Using hardcoded values instead of configuration
- ✅ Maintain all necessary complexity for production-ready code

---

## 🚫 Code Quality Anti-Patterns

### 4. Poor Naming Conventions
**NEVER** use vague or misleading names:
- ❌ Single letter variables (except loop counters)
- ❌ Generic names: `data`, `temp`, `thing`, `stuff`
- ❌ Misleading names that don't reflect purpose
- ❌ Inconsistent naming conventions within the same codebase
- ✅ Use descriptive, self-documenting names

### 5. Magic Numbers and Strings
**NEVER** use unexplained literal values:
- ❌ `if (status === 2)` without context
- ❌ `setTimeout(fn, 3000)` without explanation
- ❌ Hardcoded URLs, API keys, or configuration values
- ✅ Use named constants with clear purposes
- ✅ Store configuration in appropriate config files

### 6. Ignoring Performance
**NEVER** write obviously inefficient code:
- ❌ Nested loops without consideration (O(n²) when O(n) is possible)
- ❌ Repeated expensive calculations without caching
- ❌ Loading entire datasets when pagination is needed
- ❌ Synchronous operations that should be async
- ✅ Consider algorithmic complexity
- ✅ Implement appropriate caching strategies

---

## 🚫 Architecture Anti-Patterns

### 7. Tight Coupling
**NEVER** create unnecessary dependencies:
- ❌ Direct database queries in UI components
- ❌ Business logic in view layers
- ❌ Hardcoded dependencies instead of dependency injection
- ❌ Circular dependencies
- ✅ Follow separation of concerns
- ✅ Use appropriate design patterns

### 8. Security Shortcuts
**NEVER** compromise security for convenience:
- ❌ Storing sensitive data in plaintext
- ❌ Client-side only validation
- ❌ SQL concatenation instead of parameterized queries
- ❌ Exposing sensitive information in error messages
- ❌ Using deprecated or vulnerable dependencies
- ✅ Always implement proper security measures

### 9. Copy-Paste Programming
**NEVER** duplicate code without abstraction:
- ❌ Copying code blocks instead of creating functions
- ❌ Duplicating similar logic across files
- ❌ Not following DRY (Don't Repeat Yourself) principles
- ✅ Extract common functionality into reusable components

---

## 🚫 Documentation Anti-Patterns

### 10. Missing or Misleading Documentation
**NEVER** skip essential documentation:
- ❌ No comments for complex logic
- ❌ Outdated comments that don't match code
- ❌ Missing API documentation
- ❌ No README or setup instructions
- ✅ Document complex algorithms and business logic
- ✅ Keep documentation synchronized with code

### 11. Over-commenting Obvious Code
**NEVER** add redundant comments:
- ❌ `i++; // increment i`
- ❌ `return true; // returns true`
- ✅ Comment WHY, not WHAT
- ✅ Focus on business logic and complex decisions

---

## 🚫 Testing Anti-Patterns

### 12. Insufficient Testing
**NEVER** skip testing considerations:
- ❌ No unit tests for critical functions
- ❌ Testing only happy paths
- ❌ Commented out or skipped tests
- ❌ Tests that always pass regardless of implementation
- ✅ Write comprehensive tests for edge cases
- ✅ Maintain adequate test coverage

---

## 🚫 Communication Anti-Patterns

### 13. Making Assumptions
**NEVER** assume requirements without clarification:
- ❌ Guessing user intentions
- ❌ Choosing technologies without considering constraints
- ❌ Assuming environment or deployment details
- ✅ Ask for clarification when requirements are ambiguous
- ✅ Document assumptions explicitly

### 14. Overengineering
**NEVER** add unnecessary complexity:
- ❌ Using complex patterns for simple problems
- ❌ Adding features not requested
- ❌ Premature optimization
- ❌ Over-abstracting simple logic
- ✅ Follow YAGNI (You Aren't Gonna Need It)
- ✅ Start simple and refactor when needed

---

## 📋 Quick Reference Checklist

Before generating or modifying code, ensure:

- [ ] No placeholder or mock implementations
- [ ] Proper error handling implemented
- [ ] Descriptive variable and function names used
- [ ] No magic numbers or hardcoded values
- [ ] Security best practices followed
- [ ] Code is DRY (no unnecessary duplication)
- [ ] Complex logic is documented
- [ ] Performance implications considered
- [ ] Proper separation of concerns maintained
- [ ] Testing approach considered
- [ ] No assumptions made without clarification

---

## 🎯 Core Principles to Follow

1. **Complete over Convenient**: Always provide complete, working solutions
2. **Explicit over Implicit**: Make intentions and behaviors clear
3. **Secure by Default**: Never compromise security for simplicity
4. **Maintainable over Clever**: Prioritize readability and maintainability
5. **Ask, Don't Assume**: Clarify ambiguous requirements

---

*This document should be referenced by AI code assistants to ensure high-quality, production-ready code generation that avoids common pitfalls and anti-patterns.*