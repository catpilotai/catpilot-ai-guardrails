# Rails Security Guardrails — Full Reference

> **Version:** 1.0.0 | **Condensed:** [condensed.md](./condensed.md)

This document provides detailed security patterns for Ruby on Rails applications.

---

## Table of Contents

1. [SQL Injection](#sql-injection)
2. [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)
3. [Mass Assignment](#mass-assignment)
4. [CSRF Protection](#csrf-protection)
5. [Command Injection](#command-injection)
6. [Authentication & Authorization](#authentication--authorization)
7. [Session Security](#session-security)
8. [File Uploads](#file-uploads)

---

## SQL Injection

### ❌ Vulnerable Patterns

```ruby
# String interpolation in queries
User.where("name = '#{params[:name]}'")
User.where("email LIKE '%#{params[:search]}%'")

# Direct string concatenation
User.find_by_sql("SELECT * FROM users WHERE id = " + params[:id])

# Even with sanitize, easy to miss edge cases
User.where("role = '#{sanitize(params[:role])}'")  # Can still be wrong
```

### ✅ Safe Patterns

```ruby
# Hash conditions (parameterized automatically)
User.where(name: params[:name])
User.where(email: params[:email], active: true)

# Array conditions with placeholders
User.where("name = ? AND role = ?", params[:name], params[:role])
User.where("email LIKE ?", "%#{User.sanitize_sql_like(params[:search])}%")

# Named placeholders
User.where("created_at > :date", date: params[:start_date])

# Arel for complex queries
users = User.arel_table
User.where(users[:name].matches("%#{User.sanitize_sql_like(search)}%"))
```

---

## Cross-Site Scripting (XSS)

### The Problem

Rails auto-escapes ERB output by default, but several patterns bypass this protection.

### ❌ Vulnerable Patterns

```erb
<%# raw() bypasses escaping %>
<%= raw(user.bio) %>

<%# html_safe marks string as safe (dangerous on user input) %>
<%= user.comment.html_safe %>

<%# content_tag with user input in certain positions %>
<%= content_tag(:div, id: params[:id]) do %>  <%# id attribute not escaped properly %>

<%# link_to with javascript: protocol %>
<%= link_to "Click", params[:url] %>  <%# Could be javascript:alert(1) %>
```

### ✅ Safe Patterns

```erb
<%# Default ERB escapes automatically %>
<%= user.bio %>
<%= user.comment %>

<%# Sanitize HTML if you need some tags %>
<%= sanitize(user.bio, tags: %w[b i em strong], attributes: %w[]) %>

<%# Validate URLs before using %>
<% if valid_http_url?(params[:url]) %>
  <%= link_to "Click", params[:url] %>
<% end %>

<%# Use content_tag safely %>
<%= content_tag(:div, user.content, id: dom_id(user)) %>
```

```ruby
# Helper for URL validation
def valid_http_url?(url)
  uri = URI.parse(url)
  uri.is_a?(URI::HTTP) || uri.is_a?(URI::HTTPS)
rescue URI::InvalidURIError
  false
end
```

---

## Mass Assignment

### The Problem

Without Strong Parameters, attackers can set any model attribute.

### ❌ Vulnerable Patterns

```ruby
# Directly using params (Rails 3 style, still possible to do wrong)
User.create(params[:user])
@user.update(params[:user])

# Permitting too much
def user_params
  params.require(:user).permit!  # Permits EVERYTHING
end

# Permitting sensitive fields
def user_params
  params.require(:user).permit(:name, :email, :role, :admin)  # role/admin shouldn't be here!
end
```

### ✅ Safe Patterns

```ruby
# Strong Parameters with explicit allowlist
def user_params
  params.require(:user).permit(:name, :email, :password, :password_confirmation)
end

# Different params for different actions
def user_params
  if current_user.admin?
    params.require(:user).permit(:name, :email, :role)
  else
    params.require(:user).permit(:name, :email)
  end
end

# Nested attributes carefully
def post_params
  params.require(:post).permit(:title, :body, comments_attributes: [:id, :content, :_destroy])
end
```

---

## CSRF Protection

### ❌ Vulnerable Patterns

```ruby
# Disabling CSRF globally
class ApplicationController < ActionController::Base
  skip_before_action :verify_authenticity_token  # DANGEROUS
end

# Disabling for specific actions without good reason
class PaymentsController < ApplicationController
  skip_before_action :verify_authenticity_token, only: [:webhook]  # OK for webhooks with signature verification
end
```

### ✅ Safe Patterns

```ruby
# Default CSRF protection (keep it!)
class ApplicationController < ActionController::Base
  protect_from_forgery with: :exception
end

# For APIs, use token-based auth instead
class ApiController < ActionController::Base
  skip_before_action :verify_authenticity_token
  before_action :authenticate_api_token!  # Your token auth
end

# For webhooks, verify signatures
class WebhooksController < ApplicationController
  skip_before_action :verify_authenticity_token
  before_action :verify_webhook_signature!
  
  private
  
  def verify_webhook_signature!
    signature = request.headers['X-Signature']
    payload = request.raw_post
    expected = OpenSSL::HMAC.hexdigest('SHA256', ENV['WEBHOOK_SECRET'], payload)
    head :unauthorized unless ActiveSupport::SecurityUtils.secure_compare(signature, expected)
  end
end
```

---

## Command Injection

### ❌ Vulnerable Patterns

```ruby
# String interpolation in system calls
system("ls #{params[:dir]}")
`grep #{params[:pattern]} file.txt`
exec("convert #{params[:filename]} output.png")
IO.popen("cat #{user_input}")

# Even with shell escaping, risky
system("ls #{Shellwords.escape(params[:dir])}")  # Better but still prefer array form
```

### ✅ Safe Patterns

```ruby
# Array form (no shell interpretation)
system('ls', '-la', directory)
system('grep', pattern, 'file.txt')

# Open3 for capturing output safely
require 'open3'
stdout, stderr, status = Open3.capture3('ls', '-la', directory)

# For ImageMagick, use MiniMagick gem (handles escaping)
image = MiniMagick::Image.open(uploaded_file.path)
image.resize "100x100"
```

---

## Authentication & Authorization

### Devise Best Practices

```ruby
# config/initializers/devise.rb
Devise.setup do |config|
  config.password_length = 12..128  # Require strong passwords
  config.lock_strategy = :failed_attempts
  config.maximum_attempts = 5
  config.unlock_strategy = :time
  config.unlock_in = 1.hour
  config.timeout_in = 30.minutes
end
```

### Authorization with Pundit

```ruby
# Always authorize in controllers
class PostsController < ApplicationController
  def show
    @post = Post.find(params[:id])
    authorize @post  # Raises if not authorized
  end
  
  def update
    @post = Post.find(params[:id])
    authorize @post
    @post.update(post_params)
  end
end

# Policy class
class PostPolicy < ApplicationPolicy
  def show?
    true  # Anyone can view
  end
  
  def update?
    record.user == user || user.admin?  # Only owner or admin
  end
end
```

### Ensure Authorization Everywhere

```ruby
# In ApplicationController
class ApplicationController < ActionController::Base
  include Pundit::Authorization
  after_action :verify_authorized, except: :index
  after_action :verify_policy_scoped, only: :index
end
```

---

## Session Security

```ruby
# config/initializers/session_store.rb
Rails.application.config.session_store :cookie_store,
  key: '_myapp_session',
  secure: Rails.env.production?,      # HTTPS only in prod
  httponly: true,                      # No JS access
  same_site: :lax                      # CSRF protection

# Force SSL in production
# config/environments/production.rb
config.force_ssl = true
```

---

## File Uploads

### With Active Storage

```ruby
# Validate content type
class User < ApplicationRecord
  has_one_attached :avatar
  
  validate :acceptable_avatar
  
  private
  
  def acceptable_avatar
    return unless avatar.attached?
    
    unless avatar.content_type.in?(%w[image/png image/jpeg image/gif])
      errors.add(:avatar, 'must be PNG, JPEG, or GIF')
    end
    
    if avatar.byte_size > 5.megabytes
      errors.add(:avatar, 'must be less than 5MB')
    end
  end
end
```

### Validate File Names

```ruby
# Sanitize uploaded filenames
def safe_filename(filename)
  # Remove directory components and null bytes
  File.basename(filename).gsub(/[\x00\/\\]/, '')
end
```

---

## Quick Reference

| Vulnerability | Rails Protection |
|---------------|------------------|
| SQL Injection | Hash conditions, placeholders |
| XSS | Auto-escaping (avoid `raw`, `html_safe`) |
| Mass Assignment | Strong Parameters |
| CSRF | `protect_from_forgery` (default) |
| Session Hijacking | `secure: true`, `httponly: true` |

---

*Condensed version: [condensed.md](./condensed.md)*
