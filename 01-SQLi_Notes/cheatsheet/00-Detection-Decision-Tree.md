# SQL Injection — Detection Decision Tree

## 1\. Purpose

This document provides a practical decision-making workflow for identifying and investigating potential SQL Injection (SQLi) vulnerabilities during authorized penetration testing and bug bounty assessments.

The objective is not to memorize payloads. It is to understand:

- Where to test.
- What behavior to observe.
- Which SQLi technique to investigate.
- Why a particular technique is appropriate.
- How to validate suspicious behavior.
- When to stop testing and document findings.

**Core principle:**

Observe → Form a hypothesis → Test → Compare → Validate → Report.

---

## 2\. Initial Assessment

Before testing SQL Injection, understand the application's input handling and normal behavior.

### Step 1: Identify Input Points

Look for user-controlled input in:

- URL query parameters.
- POST body parameters.
- JSON request bodies.
- HTTP cookies.
- HTTP headers.
- Search functionality.
- Filtering and sorting functionality.
- Login and registration forms.
- Product IDs and category filters.
- API endpoints.

Example:

``` http
GET /products?id=15 HTTP/1.1
Host: target.example
```

Potential injection point:

``` text
id=15
```

Do not assume every parameter interacts with a database.

### Step 2: Establish a Baseline

Send the original request without modifications.

Record:

- HTTP status code.
- Response body.
- Response length.
- Response structure.
- Response time.
- Application behavior.

Example:

``` text
Request:  /products?id=15
Status:   200
Response: Product information returned
Time:     180 ms
```

The baseline is essential because subsequent tests must be compared against normal behavior.

---

## 3\. Initial Input Testing

Perform controlled input modifications.

Example:

Original:

``` text
?id=15
```

Modified:

``` text
?id=16
?id=abc
?id=15'
?id=15"
```

Observe:

| Observation | Possible explanation |
| --- | --- |
| Different product returned | Normal application behavior |
| Generic error | Application validation or backend error |
| SQL error message | Possible SQL Injection |
| HTTP 500 | Possible backend exception |
| HTTP 403 | Possible WAF or access-control block |
| No visible difference | Input may be ignored or response may be unchanged |
| Response delay | Possible processing delay; requires further investigation |

Important:

A single HTTP 500, 403, or response delay does not prove SQL Injection.

---

## 4\. SQLi Detection Decision Tree

Use the following decision process to select the next investigation technique.

``` text
                    START
                      |
                      v
             Identify input point
                      |
                      v
              Establish baseline
                      |
                      v
             Modify input safely
                      |
                      v
             Observe response
                      |
          +-----------+-----------+
          |           |           |
          v           v           v
      SQL Error   Content       Delay
       Visible    Difference    Observed
          |           |           |
          v           v           v
      Investigate  Boolean     Investigate
      Error-Based  Testing     Time-Based
          |           |           |
          +-----------+-----------+
                      |
                      v
             No clear evidence?
                      |
                      v
          Investigate other contexts
                      |
          +-----------+-----------+
          |           |           |
          v           v           v
       UNION       Second-Order   OOB
       Testing      Testing      Testing
          |           |           |
          +-----------+-----------+
                      |
                      v
             Validate evidence
                      |
                      v
               Document result
```

This is a conceptual workflow, not a mandatory linear sequence. Technique selection depends on the application's behavior and the evidence collected.

---

## 5\. Technique Selection Guide

### 5.1 Error-Based SQL Injection

**When to investigate:**

- Database error messages appear.
- Input modifications trigger database-related errors.
- SQL syntax or database-specific error information is exposed.

**What to investigate:**

- Does the error originate from the database?
- Is the error reproducible?
- Does changing the input change the error behavior?
- Can the error be distinguished from ordinary application exceptions?

**Next step:**

Determine whether the application exposes database error information and whether user input influences query execution.

Do not confuse generic HTTP 500 errors with database errors.

### 5.2 Boolean-Based Blind SQL Injection

**When to investigate:**

- No database error is displayed.
- Different input conditions produce different application responses.
- Response content, length, structure, or behavior changes consistently.

**What to investigate:**

- Can two logically different conditions produce distinguishable responses?
- Is the difference repeatable?
- Could caching, authentication, dynamic content, or application logic explain the difference?

**Next step:**

Compare true and false conditions while keeping other request variables constant.

A reliable and reproducible difference is stronger evidence than a single response variation.

### 5.3 Conditional Error-Based SQL Injection

**When to investigate:**

- No useful content difference is visible.
- The application produces different error behavior under certain conditions.
- Database errors may be suppressed or converted into generic responses.

**What to investigate:**

- Does a specific condition consistently trigger an error?
- Does the opposite condition avoid that error?
- Is the behavior related to database query execution?

**Next step:**

Establish a reproducible conditional difference and eliminate ordinary application-level errors.

### 5.4 Time-Based Blind SQL Injection

**When to investigate:**

- No useful content difference exists.
- Database errors are not exposed.
- The application response appears to depend on backend processing.
- Timing differences may indicate conditional query execution.

**What to investigate:**

- Is the delay repeatable?
- Does the delay occur only under a particular condition?
- Are there network or server-load variations?
- Does the baseline have stable response times?

**Next step:**

Use repeated controlled measurements and compare conditional and non-conditional behavior.

A single slow response is not sufficient evidence.

### 5.5 UNION-Based SQL Injection

**When to investigate:**

- There is evidence that input influences a database query.
- Query results appear in the application's response.
- The application may render database query output.

**What to investigate:**

- Is the injection context compatible with a UNION operation?
- Can the number of selected columns be established?
- Are compatible data types required?
- Does the application display returned query data?

**Next step:**

Investigate query structure and whether controlled database output can be demonstrated safely.

UNION-based testing is not always appropriate, especially when the application does not expose query results.

### 5.6 Second-Order SQL Injection

**When to investigate:**

- Input is stored successfully.
- No immediate SQLi behavior appears.
- The stored input is used later by another application function.
- A different user or administrative workflow may process the stored value.

**Potential locations:**

- User profile information.
- Product reviews.
- Support tickets.
- Saved searches.
- Order information.
- Administrative management interfaces.

**What to investigate:**

- Where is the input stored?
- Which later workflow retrieves it?
- Does another database operation use the stored value?
- Can the behavior be reproduced during that later operation?

**Next step:**

Trace the input lifecycle from submission to storage to later processing.

### 5.7 Out-of-Band SQL Injection (OOB)

**When to investigate:**

- Direct responses provide no useful evidence.
- Error messages are suppressed.
- The database or application environment may support external interactions.
- A controlled external callback could provide evidence.

**What to investigate:**

- Is the relevant database behavior capable of external interaction?
- Is outbound network communication permitted?
- Does a unique callback correlate with the test request?
- Could DNS resolution, proxies, or unrelated background traffic explain the callback?

**Next step:**

Use an authorized OOB interaction service and correlate unique interactions with individual test requests.

A callback alone must be interpreted carefully.

---

## 6\. WAF Detection and Decision-Making

A WAF can inspect or block suspicious requests before they reach the application.

Common observations:

| Observation | Possible explanation |
| --- | --- |
| HTTP 403 | WAF or application access control |
| HTTP 406 | Request filtering |
| HTTP 429 | Rate limiting |
| CAPTCHA | Automated-request protection |
| Custom block page | Security gateway |
| Connection reset | Network or security filtering |
| Normal response | Request was not visibly blocked |

### What to do when WAF blocks a request

1. Preserve the original request.
2. Record the exact response.
3. Compare it with a normal request.
4. Identify which input or request modification triggered the block.
5. Check whether the block is consistent.
6. Identify other legitimate application input paths within scope.
7. Consult the program's testing policy before attempting security-control bypasses.

### Important distinction

``` text
WAF Blocked Request
        |
        v
Does not prove SQLi exists
        |
        v
Does not prove SQLi is absent
        |
        v
Continue evidence-driven assessment
```

Do not spend the entire assessment attempting random WAF bypass payloads.

WAF bypass and SQLi detection are separate investigation activities.

---

## 7\. Database Fingerprinting

Database-specific behavior can help select appropriate testing methods.

Common database management systems:

| DBMS | Common identification clues |
| --- | --- |
| MySQL | MySQL-specific error messages and behavior |
| PostgreSQL | PostgreSQL-specific errors and syntax |
| Microsoft SQL Server | SQL Server error messages and behavior |
| Oracle | Oracle-specific errors and syntax |
| SQLite | SQLite-specific error messages and behavior |

### Important

- Do not assume the DBMS from the application's technology stack.
- Error messages can be modified or hidden.
- A database fingerprint should be supported by evidence.
- Avoid relying on a single identification clue.

---

## 8\. False Positive Elimination

Before reporting SQL Injection, investigate alternative explanations.

Common false-positive sources:

- Input validation errors.
- Application-level exceptions.
- WAF responses.
- CDN caching.
- Rate limiting.
- Network instability.
- Dynamic response content.
- Session expiration.
- Backend performance fluctuations.

### Validation Checklist

- [ ] Original request works consistently.
- [ ] Modified request produces a reproducible difference.
- [ ] Difference is related to the tested input.
- [ ] Alternative explanations have been investigated.
- [ ] Evidence is repeatable.
- [ ] Impact is demonstrated without unnecessary data access.
- [ ] Testing remained within the authorized scope.

---

## 9\. Choosing the Next Technique: Quick Reference

| Situation | Investigation direction |
| --- | --- |
| Database error exposed | Error-Based |
| True/False response difference | Boolean-Based |
| Conditional error difference | Conditional Error-Based |
| Repeatable conditional delay | Time-Based |
| Query output reflected in response | UNION-Based |
| Stored input executes later | Second-Order |
| Correlated external interaction | OOB |
| Request blocked by WAF | Analyze filtering and application behavior first |
| No observable behavior | Reassess input point and execution context |

Remember:

These techniques are not mutually exclusive. One SQLi vulnerability may support multiple detection methods.

---

## 10\. Reporting and Documentation

Once a vulnerability is validated, document:

### Finding Information

- Vulnerability: SQL Injection
- Endpoint: Affected endpoint
- Parameter: Vulnerable input
- HTTP Method: GET / POST / etc.
- SQLi Type: Confirmed technique
- Database: If identified
- Authentication: Required / Not required

### Evidence

Include:

1. Original HTTP request.
2. Modified HTTP request.
3. Original response.
4. Modified response.
5. Relevant differences.
6. Reproduction steps.
7. Impact demonstration.
8. Supporting screenshots where appropriate.

### Impact

Explain the actual security consequences supported by evidence.

Potential impacts may include:

- Unauthorized database information access.
- Exposure of sensitive records.
- Authentication-related compromise.
- Unauthorized modification of data.
- Database-level privilege abuse.

Do not claim an impact that has not been demonstrated or reasonably established.

---

## 11\. Practical Testing Mindset

The biggest mistake during SQLi testing is thinking:

"Which payload should I try next?"

Instead, ask:

1. What do I currently know about this input?
2. What behavior am I trying to investigate?
3. Why is this technique appropriate?
4. What result would support my hypothesis?
5. What result would contradict my hypothesis?
6. What should I investigate next?

### Final Principle

**Never choose a payload before understanding what you are testing.**

A good penetration tester does not simply execute payloads.

A good penetration tester observes application behavior, develops hypotheses, performs controlled experiments, validates findings, and documents reproducible evidence.

The decision-making process is more important than memorizing hundreds of payloads.
