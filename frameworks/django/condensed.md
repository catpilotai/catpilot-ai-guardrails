# Django Security Patterns

| Risk | Bad | Good |
|------|-----|------|
| SQL Injection | `User.objects.raw(f"SELECT * FROM users WHERE id={id}")` | `User.objects.filter(id=id)` or `.raw("...WHERE id=%s", [id])` |
| XSS | `mark_safe(user_input)` or `{% autoescape off %}` | Default escaping `{{ var }}`, use `bleach.clean()` for HTML |
| CSRF | `@csrf_exempt` on state-changing views | Keep `CsrfViewMiddleware`, use `{% csrf_token %}` |
| Mass Assignment | `User.objects.create(**request.POST)` | Use Django Forms/Serializers with explicit fields |
| Auth Bypass | Missing `@login_required` or `permission_classes` | `@login_required`, `@permission_required`, DRF permissions |
| Secrets | `SECRET_KEY = "hardcoded"` in settings.py | `SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]` |

**Reference:** `FULL_DJANGO.md` for ORM safety, DRF patterns, file upload validation
