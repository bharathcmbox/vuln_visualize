# Vulnerability brief — VP-2026-001 (lab, defensive)

This is the input handed to the drafting model. It describes the defect and the
desired mitigation at a defensive level. It contains **no exploit payloads** —
the model is asked to reason about the correct *shape* of allowed input, not to
reproduce attacks.

- **Application**: a Node/Express web app (training target).
- **Endpoint**: `POST /rest/user/login`
- **Request body**: JSON `{ "email": <string>, "password": <string> }`
- **Defect class**: the `email` field flows into a database query without being
  constrained to its expected form, enabling an authentication-bypass class of
  attack when the field is not email-shaped.
- **Upstream fix (eventual)**: parameterize the query / use an ORM binding.
- **Interim mitigation wanted**: a ModSecurity v3 (OWASP CRS, nginx connector)
  **virtual patch** that enforces a *positive security model* — on this route,
  the `email` field must match a normal email shape; anything else is denied.

## Constraints the rule MUST satisfy

1. Scope strictly to `POST /rest/user/login`. Do not affect other routes.
2. Inspect the JSON `email` argument (ModSecurity exposes it as `ARGS:json.email`).
3. Positive model: allow only email-shaped values; deny everything else.
4. Must NOT block legitimate logins (valid email + any password, including a
   wrong password — the app itself handles wrong passwords).
5. Use a CRS-compatible rule id in the 1,0xx,xxx local range.
6. Tag it `virtual-patch` and `expiry-required`.
