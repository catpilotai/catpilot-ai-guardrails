# Django Security Guardrails — Full Reference

> **Version:** 1.0.0 | **Condensed:** [condensed.md](./condensed.md)

This document provides detailed security patterns for Django applications.

---

## Table of Contents

1. [SQL Injection](#sql-injection)
2. [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)
3. [CSRF Protection](#csrf-protection)
4. [Authentication & Authorization](#authentication--authorization)
5. [Mass Assignment](#mass-assignment)
6. [Secrets Management](#secrets-management)
7. [File Uploads](#file-uploads)
8. [Django REST Framework](#django-rest-framework)

---

## SQL Injection

### ❌ Vulnerable Patterns

```python
# String formatting in raw queries
def get_user(request):
    user_id = request.GET['id']
    user = User.objects.raw(f"SELECT * FROM auth_user WHERE id = {user_id}")  # DANGEROUS
    return user[0]

# Even with extra()
User.objects.extra(where=[f"name = '{name}'"])  # DANGEROUS

# String formatting in filter
User.objects.filter(name__icontains=f"%{search}%")  # Wrong approach
```

### ✅ Safe Patterns

```python
# ORM methods (parameterized automatically)
User.objects.filter(id=user_id)
User.objects.filter(name__icontains=search)
User.objects.get(email=email)

# Raw queries with parameters
User.objects.raw("SELECT * FROM auth_user WHERE id = %s", [user_id])

# extra() with params
User.objects.extra(where=["name = %s"], params=[name])

# Using connection.cursor with params
from django.db import connection
with connection.cursor() as cursor:
    cursor.execute("SELECT * FROM auth_user WHERE id = %s", [user_id])
    row = cursor.fetchone()
```

---

## Cross-Site Scripting (XSS)

### ❌ Vulnerable Patterns

```html
{% comment %} Disabling auto-escaping {% endcomment %}
{% autoescape off %}
    {{ user_content }}
{% endautoescape %}

{% comment %} Marking as safe {% endcomment %}
{{ user_content|safe }}
```

```python
# In views
from django.utils.safestring import mark_safe
return HttpResponse(mark_safe(user_input))  # DANGEROUS
```

### ✅ Safe Patterns

```html
{% comment %} Default escaping (safe) {% endcomment %}
{{ user_content }}

{% comment %} If you need some HTML, sanitize first {% endcomment %}
{{ sanitized_content|safe }}
```

```python
# Sanitize HTML before marking safe
import bleach

ALLOWED_TAGS = ['b', 'i', 'em', 'strong', 'a', 'p', 'br']
ALLOWED_ATTRS = {'a': ['href', 'title']}

def sanitize_html(content):
    return bleach.clean(
        content,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRS,
        strip=True
    )

# Then in view
cleaned = sanitize_html(user_input)
return render(request, 'template.html', {'content': mark_safe(cleaned)})
```

---

## CSRF Protection

### ❌ Vulnerable Patterns

```python
# Disabling CSRF globally
MIDDLEWARE = [
    # 'django.middleware.csrf.CsrfViewMiddleware',  # Removed - DANGEROUS
]

# Exempting views unnecessarily
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt  # Why?
def update_profile(request):
    pass
```

### ✅ Safe Patterns

```python
# Keep CSRF middleware enabled (default)
MIDDLEWARE = [
    'django.middleware.csrf.CsrfViewMiddleware',
    # ...
]

# In templates, include token
<form method="post">
    {% csrf_token %}
    <!-- form fields -->
</form>

# For AJAX, include token in headers
// JavaScript
const csrftoken = document.querySelector('[name=csrfmiddlewaretoken]').value;
fetch('/api/update/', {
    method: 'POST',
    headers: {
        'X-CSRFToken': csrftoken,
        'Content-Type': 'application/json',
    },
    body: JSON.stringify(data)
});

# Only exempt for webhooks with signature verification
@csrf_exempt
def stripe_webhook(request):
    sig = request.headers.get('Stripe-Signature')
    try:
        event = stripe.Webhook.construct_event(
            request.body, sig, settings.STRIPE_WEBHOOK_SECRET
        )
    except ValueError:
        return HttpResponse(status=400)
    except stripe.error.SignatureVerificationError:
        return HttpResponse(status=400)
```

---

## Authentication & Authorization

### ❌ Vulnerable Patterns

```python
# Missing login requirement
def dashboard(request):
    return render(request, 'dashboard.html', {'user': request.user})

# Checking user but not ownership
@login_required
def view_document(request, doc_id):
    doc = Document.objects.get(id=doc_id)  # Anyone can view any doc!
    return render(request, 'doc.html', {'doc': doc})
```

### ✅ Safe Patterns

```python
from django.contrib.auth.decorators import login_required, permission_required
from django.core.exceptions import PermissionDenied

# Require login
@login_required
def dashboard(request):
    return render(request, 'dashboard.html')

# Require specific permission
@permission_required('app.can_edit_posts', raise_exception=True)
def edit_post(request, post_id):
    pass

# Check object ownership
@login_required
def view_document(request, doc_id):
    doc = get_object_or_404(Document, id=doc_id, owner=request.user)
    return render(request, 'doc.html', {'doc': doc})

# Or use PermissionDenied
@login_required
def view_document(request, doc_id):
    doc = get_object_or_404(Document, id=doc_id)
    if doc.owner != request.user and not request.user.is_staff:
        raise PermissionDenied
    return render(request, 'doc.html', {'doc': doc})
```

### Class-Based Views

```python
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.views.generic import DetailView

class DocumentDetailView(LoginRequiredMixin, DetailView):
    model = Document
    
    def get_queryset(self):
        # Only return user's own documents
        return Document.objects.filter(owner=self.request.user)
```

---

## Mass Assignment

### ❌ Vulnerable Patterns

```python
# Directly using request data
def create_user(request):
    User.objects.create(**request.POST)  # Can set is_staff, is_superuser!

# ModelForm without field restriction
class UserForm(forms.ModelForm):
    class Meta:
        model = User
        fields = '__all__'  # DANGEROUS
```

### ✅ Safe Patterns

```python
# Explicit fields in ModelForm
class UserRegistrationForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['username', 'email', 'password']  # Explicit allowlist
    
    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data['password'])
        if commit:
            user.save()
        return user

# In view
def register(request):
    form = UserRegistrationForm(request.POST)
    if form.is_valid():
        user = form.save()
        return redirect('login')
```

---

## Secrets Management

### ❌ Vulnerable Patterns

```python
# settings.py with hardcoded secrets
SECRET_KEY = 'django-insecure-abc123'
DATABASES = {
    'default': {
        'PASSWORD': 'mypassword',
    }
}
```

### ✅ Safe Patterns

```python
# settings.py
import os
from pathlib import Path

SECRET_KEY = os.environ['DJANGO_SECRET_KEY']

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.environ['DB_NAME'],
        'USER': os.environ['DB_USER'],
        'PASSWORD': os.environ['DB_PASSWORD'],
        'HOST': os.environ.get('DB_HOST', 'localhost'),
    }
}

# Or use django-environ
import environ
env = environ.Env()
environ.Env.read_env()

SECRET_KEY = env('DJANGO_SECRET_KEY')
DEBUG = env.bool('DEBUG', False)
DATABASES = {'default': env.db()}
```

---

## File Uploads

### ❌ Vulnerable Patterns

```python
# No validation
def upload(request):
    file = request.FILES['file']
    with open(f'/uploads/{file.name}', 'wb') as f:  # Path traversal risk
        f.write(file.read())
```

### ✅ Safe Patterns

```python
import os
import uuid
from django.core.exceptions import ValidationError

def validate_file(file):
    # Check size
    if file.size > 5 * 1024 * 1024:  # 5MB
        raise ValidationError('File too large')
    
    # Check content type
    allowed_types = ['image/jpeg', 'image/png', 'application/pdf']
    if file.content_type not in allowed_types:
        raise ValidationError('Invalid file type')

def upload(request):
    file = request.FILES['file']
    validate_file(file)
    
    # Generate safe filename
    ext = os.path.splitext(file.name)[1].lower()
    if ext not in ['.jpg', '.jpeg', '.png', '.pdf']:
        raise ValidationError('Invalid extension')
    
    safe_name = f"{uuid.uuid4()}{ext}"
    
    # Use Django's file storage
    from django.core.files.storage import default_storage
    path = default_storage.save(f'uploads/{safe_name}', file)
    return JsonResponse({'path': path})
```

---

## Django REST Framework

### Authentication

```python
# settings.py
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',  # Require auth by default
    ],
}
```

### Serializers (Mass Assignment Protection)

```python
from rest_framework import serializers

# ❌ Dangerous - all fields
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'

# ✅ Safe - explicit fields
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email']
        read_only_fields = ['id']

# ✅ Different serializers for different actions
class UserCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email', 'password']
        extra_kwargs = {'password': {'write_only': True}}

class UserDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'date_joined']
```

### Permissions

```python
from rest_framework import permissions

class IsOwnerOrReadOnly(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True
        return obj.owner == request.user

class DocumentViewSet(viewsets.ModelViewSet):
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrReadOnly]
    
    def get_queryset(self):
        return Document.objects.filter(owner=self.request.user)
```

---

## Quick Reference

| Vulnerability | Django Protection |
|---------------|------------------|
| SQL Injection | ORM methods, parameterized `.raw()` |
| XSS | Auto-escaping (avoid `\|safe`, `mark_safe`) |
| CSRF | `CsrfViewMiddleware` + `{% csrf_token %}` |
| Auth Bypass | `@login_required`, `LoginRequiredMixin` |
| Mass Assignment | Forms/Serializers with explicit `fields` |
| Secrets | `os.environ`, django-environ |

---

*Condensed version: [condensed.md](./condensed.md)*
