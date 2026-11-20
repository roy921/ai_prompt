# Firestore Security Specification (`prompts` Archive — Admin Auth Hardened)

## 1. Data Invariants
- Collection `/prompts/{promptId}` is publicly readable (`get`, `list`) by guests without authentication.
- Write operations (`create`, `update`, `delete`) on `/prompts/{promptId}` are strictly restricted to the single verified administrator (`request.auth != null && request.auth.token.email_verified == true && request.auth.token.email == 'jeh12921@gmail.com'`).
- Every prompt document ID must match `^[a-zA-Z0-9_\-]+$` and be at most 128 characters.
- Every prompt document must contain strictly the 4 allowed keys: `title`, `category`, `content`, `createdAt`.
- `title`: non-empty string, 1–120 characters.
- `category`: must be one of `'사진 합성'`, `'스타일 변환'`, `'캐릭터·포스터'`.
- `content`: non-empty string, 1–20,000 characters (supports long multi-line prompts).
- `createdAt`: Firestore server timestamp (`request.time` enforced on create; strictly immutable on update via `incoming().createdAt == existing().createdAt`).
- Updates must only affect `['title', 'category', 'content']`.

## 2. Dirty Dozen Adversarial Payloads (Expected: `PERMISSION_DENIED`)
1. Unauthenticated guest `create` attempt -> Rejected by `isAdmin()`.
2. Non-admin authenticated user (`other@gmail.com`) `create` attempt -> Rejected by `isAdmin()`.
3. Unverified email spoof (`email: 'jeh12921@gmail.com'`, `email_verified: false`) -> Rejected by `isAdmin()`.
4. Non-admin authenticated user `update` or `delete` attempt -> Rejected by `isAdmin()`.
5. Ghost field injection on create: `{ title, category, content, createdAt, isAdmin: true }` -> Rejected by `hasOnly(...)`.
6. Ghost field or `createdAt` mutation on update -> Rejected by `affectedKeys().hasOnly(['title', 'category', 'content'])` and `incoming().createdAt == existing().createdAt`.
7. Invalid category enum: `{ title: "Test", category: "기타", content: "abc", createdAt: serverTimestamp() }` -> Rejected by `category in [...]`.
8. Oversized content (>20,000 chars) or oversized title (>120 chars) -> Rejected by `.size()` bounds.
9. Empty title or empty content -> Rejected by `.size() >= 1`.
10. Client-forged timestamp on create: `createdAt: new Date("2020-01-01")` -> Rejected by `incoming().createdAt == request.time`.
11. Malformed document ID poisoning: `/prompts/bad$id!@#` -> Rejected by `isValidId(promptId)`.
12. Write to undeclared collection `/admins/attacker` -> Rejected by global default-deny catch-all.
