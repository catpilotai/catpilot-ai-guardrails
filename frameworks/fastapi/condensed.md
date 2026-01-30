## 🐍 FastAPI Security

| Risk | ❌ Never | ✅ Always |
|------|----------|----------|
| SQL Injection | `f"SELECT * FROM users WHERE id={user_id}"` | SQLAlchemy ORM or `text(:id).bindparams(id=user_id)` |
| Path Traversal | `open(f"uploads/{filename}")` | `Path(filename).name` + validate in allowed dir |
| Secrets | `SECRET_KEY = "hardcoded"` | `settings.secret_key` from env via Pydantic |
| No Auth | Endpoints without `Depends()` | `Depends(get_current_user)` on protected routes |
| Pickle | `pickle.loads(request_body)` | Pydantic models for validation |

**Auth:** Use `OAuth2PasswordBearer` + JWT. Always validate with `Depends(get_current_active_user)`.

*Full reference: [FULL_FASTAPI.md](./FULL_FASTAPI.md)*
