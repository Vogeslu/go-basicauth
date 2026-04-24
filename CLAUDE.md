# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

`github.com/mxcd/go-basicauth` is a session-based authentication library for Gin. Consumers provide their own `Storage` implementation (DB-backed user CRUD); this library handles registration, login, logout, session cookies, password hashing (Argon2id), and path-based access control middleware.

## Common Commands

Tasks are defined in `justfile`:

- `just test` — run full test suite (`go test ./... -v`)
- `just test-short` — skip long-running tests
- `just test-race` — race detector
- `just test-coverage-html` — generate `coverage.html`
- `just check` — `fmt` + `vet` + `test`
- `just example` — run `examples/simple/main.go` (in-memory storage demo)

Run a single test: `go test -run TestName ./...` or `go test -run TestFunc/subtest_name -v ./...`.

Go version is pinned to `1.25.4` in `go.mod`.

## Architecture

### Core flow

`NewHandler(*Options)` builds a `Handler` wrapping a `gorilla/sessions.CookieStore`. Session keys are validated strictly: **secret key must be exactly 64 bytes, encryption key exactly 32 bytes** — use `GenerateSessionSecretKey()` / `GenerateSessionEncryptionKey()`.

`handler.RegisterRoutes()` does two things:
1. Installs `RequireAuth()` as global middleware on the Gin engine (`engine.Use`). This is intentional — all paths go through the auth gate, which internally whitelists `/auth/register` and `/auth/login`.
2. Registers the `/auth/{register,login,logout,me}` endpoints under `AuthenticationBaseUrl` (default `/auth`).

Because `RequireAuth` is applied globally in `RegisterRoutes`, **do not also call `handler.RequireAuth()` manually on route groups** — it would run twice. Path access is configured via `Settings.PathRules` instead.

### Path-based access control

`RequireAuth` resolves access for each request in `handler.go` via `findLongestMatchingRule`:
- Hardcoded: `/auth/register` and `/auth/login` are always public; `/auth/logout` and `/auth/me` are always protected.
- For everything else, it collects rules from both `Settings.PublicPaths` (legacy, treated as public) and `Settings.PathRules`, matches by exact or prefix, and **the longest matching path wins**.
- No rule match → auth required (secure default).

This precedence is the key invariant — tests in `middleware_test.go` assert it. When adding rules, don't assume ordering; assume "most specific path wins."

### User in context

Two layers, both set by `RequireAuth` (and by login/register handlers) after successful auth:

1. **Gin context** — `c.Set("user", *User)`, retrieved via `GetUserFromContext(c)`. Used internally by `handleMe`.
2. **`context.Context`** — only if `Options.UserKey` is set. Optional `Options.UserTransformer` converts `*basicauth.User` to a consumer-defined type before storage. Use a custom unexported key type to avoid collisions.

The context.Context path is the idiomatic one for downstream handlers; the Gin-context path is kept for backward compatibility and for `/auth/me`.

### Storage interface

`Storage` (in `storage_interface.go`) is the consumer's integration point — `Create/Get{Username,Email,ID}/Update/Delete`. `NewMemoryStorage()` exists for tests and the `examples/simple` demo; it is not production-ready.

### Password hashing

Argon2id via `util.go`. `DefaultPasswordHashingParams` is used unless `Settings.HashingParams` is overridden. `VerifyPassword` returns `(valid, needsRehash, err)` — the `needsRehash` signal is currently not acted on by the handler.

## Files

- `handler.go` — `NewHandler`, route registration, `RequireAuth`, register/login/logout/me
- `types.go` — `User`, requests/responses, `BasicAuthSettings`, `DefaultSettings`, sentinel errors
- `storage_interface.go` / `storage_memory.go` — storage contract + in-memory impl
- `util.go` — Argon2id hashing + session key generation
- `validation.go` — username/email/password validators
- `context.go` — `GetUserFromContext` (Gin context helper)
- `e2e_test.go`, `middleware_test.go`, `user_context_provider_test.go`, `validation_test.go`, `util_test.go` — tests

## Conventions

- Error messages to clients come from `Settings.Messages` — keep them generic (the library deliberately avoids user-enumeration leaks; e.g., `handleLogin` returns the same `invalid_credentials` for missing user and wrong password).
- Sentinel errors (`ErrUserAlreadyExists`, etc.) are returned by `Storage` implementations and validators; handler code maps them to HTTP responses.
- Public API surface is the package root — no internal packages. Changes to `Options`, `BasicAuthSettings`, or `Storage` are breaking.
