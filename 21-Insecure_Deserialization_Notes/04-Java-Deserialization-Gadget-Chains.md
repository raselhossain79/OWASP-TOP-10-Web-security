# 04 — Java Deserialization and Gadget Chains

## 1. Java's Native Serialization Mechanism

Java has built-in object serialization independent of any third-party library. Any class that
implements the `Serializable` marker interface can be serialized:

```java
ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("data.ser"));
out.writeObject(myObject);
```

And deserialized:

```java
ObjectInputStream in = new ObjectInputStream(new FileInputStream("data.ser"));
Object obj = in.readObject(); // <-- THE deserialization sink
```

`readObject()` is the source you're looking for during code review or black-box analysis. The
moment attacker-controlled bytes reach this call, you have a candidate vulnerability.

### Recognizing serialized Java data on the wire

Java's serialization format always begins with the magic bytes `AC ED 00 05` (the "stream magic"
plus version). When this raw byte stream gets Base64-encoded (the common case for cookies/HTTP
parameters), those bytes consistently decode to a Base64 string starting with `rO0`. **Seeing
`rO0` at the start of a Base64 blob in a cookie or parameter is an immediate, high-confidence
signal of Java native serialization** — check for this during recon exactly the way you'd check
for `O:` in a PHP context.

## 2. The Automatic Call Point: `readObject()`

By default, Java's deserialization just reconstructs an object's fields with no extra code
running. The hook that makes gadget chains possible is that **any class is allowed to define
its own custom `readObject()` method**, which the deserialization machinery will call instead
of (well, technically in addition to, via `defaultReadObject()`) the default behavior:

```java
private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.defaultReadObject(); // restores fields normally
    // ... then arbitrary custom logic the class author wrote, which runs automatically
    //     the instant this class type is deserialized.
}
```

This is conceptually identical to PHP's `__wakeup()` (File 03) and Python's `__reduce__`
(File 06): a method that the *language runtime* invokes automatically purely because an object
of that class showed up in the input stream, never because application code explicitly called
it.

## 3. Why Java Chains Are (Almost) Always Library-Based, Not App-Based

Unlike PHP, where you can often build a workable POP chain purely from an application's own MVC
classes, Java applications rarely define a custom `readObject()` that's directly dangerous.
What makes Java deserialization so consistently exploitable in practice is that **enormous,
widely-used libraries ship classes with custom `readObject()` implementations that, combined
with other classes in the same library, form a complete RCE chain** — entirely independent of
what the target application's own code does.

The single most famous example: **Apache Commons Collections**. Its `InvokerTransformer` class
has a `transform()` method that uses Java reflection to call an arbitrary method, by name, on
an arbitrary object — which is normal, intended functionality for a generic collections-
manipulation library. Chained together with other Commons Collections classes whose
`readObject()`/`hashCode()`/`equals()` paths eventually call `transform()` on attacker-supplied
data during deserialization, the result is a chain that ends in:

```java
Runtime.getRuntime().exec(<attacker-controlled command>)
```

— purely from deserializing one crafted object, on **any** application that has Commons
Collections on its classpath and a reachable `readObject()` sink, regardless of what that
application is actually for. This is exactly the scenario PortSwigger's *Exploiting Java
deserialization with Apache Commons* lab simulates, and exactly why this single library caused
RCE findings across an enormous number of unrelated Java applications when it was first
disclosed around 2015.

Other libraries with known public gadget chains include Spring (Spring Beans/Spring AOP
chains), Groovy, Hibernate, C3P0, and many more — ysoserial (File 05) ships pre-built chains for
most of them.

## 4. How a Chain Actually Walks, Conceptually

You don't need to trace every line of Commons Collections to use it via ysoserial, but
understanding the shape matters for engagement reporting and for the Expert-tier custom-chain
skill:

```
ObjectInputStream.readObject()
  → deserializes a java.util.PriorityQueue (a normal JDK class, used purely as a trigger)
    → PriorityQueue's own readObject() calls compare() on its elements while restoring
      the heap order (legitimate normal PriorityQueue behavior)
      → the "comparator" was crafted to be a Commons Collections class whose compare()
        path eventually calls InvokerTransformer.transform()
        → transform() was configured (at payload-build time) to call
          Runtime.getRuntime().exec(cmd) reflectively
          → process spawned: arbitrary command execution achieved
```

Every single step above is **legitimate, unmodified library code**. Nothing was patched,
nothing was injected. The only thing under attacker control is *which objects get wired into
which fields* — exactly the gadget chain concept from File 02, made concrete.

## 5. Java 16+ Module Access Restrictions (Why Modern Chains Need Extra Flags)

Starting with JDK 9's module system (and enforced more strictly from JDK 16 onward), reflective
access to internal JDK classes used by several classic gadget chains (e.g. ones touching
`com.sun.org.apache.xalan.internal.xsltc.trax`) is blocked by default unless explicitly opened.
This is why running modern ysoserial payload *generation* or certain chain *execution* paths on
newer JDKs requires extra `--add-opens` flags — this is broken down piece by piece in File 05,
Section 4, since it directly affects real command usage.

## 6. Identifying the Target Library/Version (Black-Box)

Before reaching for ysoserial, you need to know *which* gadget chain to even try:

- **Stack traces in error responses**: a deserialization failure often leaks the exact class
  it choked on (e.g. `ClassNotFoundException: org.apache.commons.collections.functors.
  InvokerTransformer`), which directly confirms the library is present.
- **Response headers / `Server` banners / framework fingerprinting**: identify the
  application server (Tomcat, WebLogic, JBoss) and framework (Spring, Struts) — these have
  well-documented default/bundled library sets.
- **Timing/behavioral oracle**: send each ysoserial chain's payload with a sleep/DNS-callback
  command instead of a destructive one first, and observe out-of-band callbacks (e.g. via
  Burp Collaborator) to confirm execution before committing to a destructive payload.

## 7. Real-World Notes

- This bug class is responsible for some of the most widely publicized enterprise RCE incidents
  of the last decade precisely because of the shared-library effect described in Section 3 —
  always check dependency manifests (`pom.xml`, `build.gradle`, or a leaked `WEB-INF/lib/`
  directory listing) as your first move on any Java target with a suspected deserialization
  sink.
- WebLogic, WebSphere, and Jenkins have all had high-profile CVEs in exactly this category;
  treat any Java middleware product as a strong candidate for known pre-built chains before
  attempting anything custom.
- A reachable `readObject()` sink with **no** known vulnerable library on the classpath is
  exactly when the Expert-tier custom-chain skill (source-code-dependent, File 02 Section 4.2)
  becomes necessary — this is precisely what PortSwigger's *Developing a custom gadget chain
  for Java deserialization* lab tests.

## 8. What's Next

File 05 is a complete, flag-by-flag breakdown of **ysoserial**, the tool that turns everything
in this file into an actual usable payload without you re-deriving the Commons Collections
chain from scratch every time.

---
*Sensitive topic note: none — this file is purely technical/educational security content.*
