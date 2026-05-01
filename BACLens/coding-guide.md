
# Coding Guide for Verifying BAC Lens AC and CWE Rules

## 1. Purpose

We use this coding task to check whether **BAC Lens** reports correct access-control and CWE findings.

**BAC Lens** analyzes tutorial artifacts for login, registration, dashboard, profile, account, and admin code. The tool reads HTML, Markdown, or text files. It separates the artifact by heading and code snippet. Then it reports access-control signals and vulnerability-pattern signals.

The tool supports:

- Spring
- Django

We ask coders to verify each tool output. Coders should decide whether the output is a **true positive**, **false positive**, **true negative**, or **false negative**.

## 2. Unit of Analysis

Code one unit at a time.

A unit is:

> one heading and the code snippet shown under that heading in BAC Lens.

A single heading/code unit may contain:

- one AC output;
- several AC outputs;
- one CWE output;
- several CWE outputs;
- no output.

Code each rule judgment as a separate spreadsheet row.

## 3. What Coders Check

Coders check two rule families:

1. **AC rules**
2. **CWE rules**

### 3.1 AC Rule Checks

AC rules describe whether a snippet shows access-control logic.

For each snippet, check whether BAC Lens correctly reports:

| AC Element | What to Check |
|---|---|
| Subject | Who accesses the resource. Examples: anonymous user, authenticated user, admin, owner, current principal. |
| Object | What resource the user accesses. Examples: dashboard, profile, account, admin page, user record, session state. |
| Operation | What action the code performs. Examples: login, registration, view dashboard, update profile, delete user. |
| RBAC | Whether the code checks roles or authorities. Examples: `hasRole`, `hasAuthority`, `@PreAuthorize`, `@Secured`. |
| Ownership / ABAC | Whether the code checks that the current user owns the object. Examples: `principal.getName()`, `findByIdAndUserId`, `request.user == object.owner`. |
| Workflow / Context | Whether the code checks process state. Examples: email verification, reset token, rate limit, login attempt state. |
| BAC inference | Whether the tool correctly infers vertical BAC, horizontal BAC, or context-dependent BAC. |

### 3.2 CWE Rule Checks

CWE rules describe possible vulnerability patterns.

For each snippet, check whether BAC Lens correctly reports the CWE finding.

Examples:

| CWE | What to Check |
|---|---|
| CWE-862 Missing Authorization | A protected route has no login, role, ownership, or method-level authorization check. |
| CWE-863 Incorrect Authorization | The code has an authorization check, but the check uses the wrong condition or trusts user-controlled data. |
| CWE-639 IDOR | The code uses a user-controlled identifier to read or update an object without an ownership check. |
| CWE-284 Improper Access Control | The code exposes CRUD operations or protected data without enough access-control enforcement. |
| CWE-352 CSRF | The code disables CSRF or omits CSRF protection for state-changing requests. |
| CWE-200 / CWE-359 / CWE-201 | The code exposes sensitive, private, or password-related data. |
| CWE-601 Open Redirect | The code redirects to an unvalidated `next`, `redirect`, or return URL parameter. |
| CWE-922 / CWE-540 / CWE-615 | The code stores secrets insecurely or includes sensitive values in source code or comments. |

Do not mark a CWE as correct only because the code contains a keyword. Check the route, framework context, security annotations, and surrounding tutorial text.

## 4. Classification Labels

Use one label for each rule judgment.

### 4.1 TP: True Positive

Use **TP** when BAC Lens reports a rule and the report is correct.

Example:

```java
@GetMapping("/admin")
public String adminPage() {
    return "admin";
}
````

If BAC Lens reports missing authorization for this admin route, mark **TP**. The snippet shows an admin endpoint and does not show a login or role check.

### 4.2 FP: False Positive

Use **FP** when BAC Lens reports a rule, but the report is wrong.

Example:

```java
@PreAuthorize("hasRole('ADMIN')")
@GetMapping("/admin")
public String adminPage() {
    return "admin";
}
```

If BAC Lens reports missing authorization for this route, mark **FP**. The snippet already has an admin role check.

### 4.3 TN: True Negative

Use **TN** when BAC Lens does not report a rule, and that absence is correct.

Example:

```java
@GetMapping("/login")
public String loginForm() {
    return "login";
}
```

If BAC Lens reports no missing authorization finding for this login form, mark **TN**. A login form normally needs public access.

### 4.4 FN: False Negative

Use **FN** when BAC Lens does not report a rule, but it should have reported one.

Example:

```java
@GetMapping("/profile/{id}")
public String profile(@PathVariable Long id, Model model) {
    User user = userRepository.findById(id).get();
    model.addAttribute("user", user);
    return "profile";
}
```

If BAC Lens does not report IDOR or missing ownership verification, mark **FN**. The code reads a profile by a user-controlled `id` and does not check ownership.

## 5. Coding Procedure

For each artifact:

1. Open the full HTML file or source URL.
2. Run the artifact through BAC Lens.
3. Review each heading and code snippet shown by the tool.
4. Check the AC output for that snippet.
5. Check the CWE output for that snippet.
6. Compare the tool output with the code and nearby tutorial text.
7. Assign **TP**, **FP**, **TN**, or **FN**.
8. Add one short comment that explains the decision.
9. Add one row to the spreadsheet for each rule judgment.

Coders should inspect:

* method annotations;
* class-level annotations;
* route mappings;
* Spring Security configuration;
* service-layer checks;
* repository query methods;
* ownership filters;
* template-level checks;
* tutorial text around the code.

## 6. How to Judge Ambiguous Cases

### 6.1 Partial Code

Judge the visible artifact.

If the snippet lacks authorization and the artifact does not show relevant security code elsewhere, mark the missing-authorization output as **TP**.

If another section in the same artifact protects the route, mark the missing-authorization output as **FP** and mention the location in the comment.

### 6.2 Framework Defaults

Do not assume a route has protection unless the artifact shows it.

For Spring, look for evidence such as:

* `SecurityFilterChain`
* `authorizeHttpRequests`
* `requestMatchers`
* `authenticated`
* `hasRole`
* `hasAuthority`
* `@PreAuthorize`
* `@Secured`
* `@RolesAllowed`

For Django, look for evidence such as:

* `@login_required`
* `LoginRequiredMixin`
* `@permission_required`
* `request.user.is_authenticated`
* `request.user.is_staff`
* object filtering by `request.user`

### 6.3 Login and Registration Pages

Login and registration pages usually need public access.

Do not mark public access to `GET /login`, `GET /register`, or equivalent form pages as a vulnerability unless the code exposes protected data, changes privileged state, disables protection, or creates an authorization bypass.

### 6.4 Authentication and Authorization

Authentication identifies the user. Authorization decides whether that user can access a specific object or operation.

Example:

```java
@GetMapping("/profile/{id}")
public String profile(@PathVariable Long id, Principal principal) {
    return userRepository.findById(id).get();
}
```

This code has an authentication signal because it uses `Principal`. It does not show an ownership check. If BAC Lens detects an authenticated subject, that AC output may be **TP**. If BAC Lens misses IDOR, the CWE output should receive **FN**.

### 6.5 Role Check and Ownership Check

A role check does not prove ownership.

If an authenticated user can request `/profile/{id}` and the code does not compare `id` with the current user, the snippet may still contain an IDOR risk.

### 6.6 Tutorial Text

Use tutorial text as context. If the tutorial says that security code appears later, check whether that later code actually protects the route.

If the artifact teaches an incomplete pattern at the current point, code what the artifact shows. Add the tutorial note in the comment.

## 7. Excel / CSV Reporting Format

Create one spreadsheet. Each row should represent one rule judgment for one heading/code snippet.

Use these columns exactly.

| Column Name                | Required | Description                                                                                                                                                                     |
| -------------------------- | -------: | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `source_path_or_url`       |      Yes | Full local HTML path or original tutorial URL.                                                                                                                                  |
| `heading`                  |      Yes | Heading shown by BAC Lens.                                                                                                                                                      |
| `code_snippet`             |      Yes | Exact code snippet under review. Include line numbers if available.                                                                                                             |
| `rule_family`              |      Yes | Use dropdown: `AC` or `CWE`.                                                                                                                                                    |
| `reported_rule_id_or_name` |      Yes | Rule that BAC Lens reported. For AC, use names such as `Subject`, `Object`, `Operation`, `RBAC`, `ABAC`, `Contextual`, or BAC inference name. For CWE, use the CWE ID and name. |
| `tool_output`              |      Yes | Exact output shown by BAC Lens. Use `None` when the tool produced no output.                                                                                                    |
| `classification`           |      Yes | Use dropdown: `TP`, `FP`, `TN`, or `FN`.                                                                                                                                        |
| `expected_output`          |      Yes | What BAC Lens should have reported. Use `None` if no finding should appear.                                                                                                     |
| `evidence`                 |      Yes | Short code evidence or tutorial-text evidence.                                                                                                                                  |
| `comments`                 |      Yes | Explain the decision. Mention ambiguity or cross-section context here.                                                                                                          |
| `coder_id`                 |      Yes | Coder initials or assigned coder ID.                                                                                                                                            |
| `review_date`              |      Yes | Date of coding.                                                                                                                                                                 |

## 8. Dropdown Values

Use these dropdown values for `rule_family`:

```text
AC
CWE
```

Use these dropdown values for `classification`:

```text
TP
FP
TN
FN
```

Optional review-status values:

```text
Needs discussion
Resolved
Not applicable
```

## 9. Example Rows

| source_path_or_url              | heading              | code_snippet                                                                  | rule_family | reported_rule_id_or_name        | tool_output                          | classification | expected_output                 | evidence                                                           | comments                                |
| ------------------------------- | -------------------- | ----------------------------------------------------------------------------- | ----------- | ------------------------------- | ------------------------------------ | -------------- | ------------------------------- | ------------------------------------------------------------------ | --------------------------------------- |
| `/data/tutorials/example1.html` | Admin Controller     | `@GetMapping("/admin") public String admin(){ return "admin"; }`              | CWE         | `CWE-862 Missing Authorization` | Missing authorization on admin route | TP             | `CWE-862 Missing Authorization` | Admin route has no `@PreAuthorize`, `hasRole`, or security config. | Correct finding.                        |
| `/data/tutorials/example2.html` | Admin Controller     | `@PreAuthorize("hasRole('ADMIN')") @GetMapping("/admin") ...`                 | CWE         | `CWE-862 Missing Authorization` | Missing authorization on admin route | FP             | None                            | `@PreAuthorize("hasRole('ADMIN')")` protects the endpoint.         | Rule missed method-level authorization. |
| `/data/tutorials/example3.html` | Login Page           | `@GetMapping("/login") public String login(){ return "login"; }`              | CWE         | None                            | None                                 | TN             | None                            | Login form is public by design.                                    | Correct no finding.                     |
| `/data/tutorials/example4.html` | Profile Controller   | `@GetMapping("/profile/{id}") User u = repo.findById(id).get();`              | CWE         | None                            | None                                 | FN             | `CWE-639 IDOR`                  | User-controlled `id` reads profile without ownership check.        | Tool missed IDOR.                       |
| `/data/tutorials/example5.html` | Dashboard Controller | `@GetMapping("/dashboard") public String dashboard(Authentication auth){...}` | AC          | `Subject`                       | Authenticated User                   | TP             | Authenticated User              | `Authentication auth` indicates an authenticated subject.          | Correct AC extraction.                  |

## 10. Comment Rules

Write short comments with direct evidence.

Good comments:

* `Correct: admin endpoint has no role or authentication guard.`
* `False positive: class-level @PreAuthorize protects all methods in this controller.`
* `False negative: user-controlled id reaches findById without principal ownership check.`
* `Ambiguous: later security config protects /dashboard; see section SecurityConfig.`
* `Correct no finding: login GET endpoint needs public access.`

Avoid comments such as:

* `Wrong.`
* `Looks okay.`
* `Maybe vulnerable.`
* `Need to check.`

## 11. Quality Check Before Submission

Before submitting the spreadsheet, check that:

1. Every row has `source_path_or_url`.
2. Every row has `heading`.
3. Every row has `code_snippet`.
4. Every row uses only `AC` or `CWE`.
5. Every row uses only `TP`, `FP`, `TN`, or `FN`.
6. Every `FP` explains why the tool output is wrong.
7. Every `FN` states the expected rule output.
8. Every code snippet has enough context for a second reviewer.
9. The file has both `.xlsx` and `.csv` versions.

## 12. Final Deliverable

Submit one spreadsheet with all coded judgments.

Use this file name format:

```text
bac_lens_rule_verification_<coder_id>_<date>.xlsx
```

Also export a CSV version:

```text
bac_lens_rule_verification_<coder_id>_<date>.csv
```

