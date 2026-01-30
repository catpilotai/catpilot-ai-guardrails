## 🔶 Rails Security

| Risk | ❌ Never | ✅ Always |
|------|----------|----------|
| SQL Injection | `User.where("name = '#{params[:name]}'")` | `User.where(name: params[:name])` |
| XSS | `raw(user_input)` or `html_safe` on input | ERB auto-escapes: `<%= user_input %>` |
| Mass Assignment | `User.create(params[:user])` | Strong params: `params.require(:user).permit(:name)` |
| CSRF | `skip_before_action :verify_authenticity_token` | Keep CSRF protection enabled |
| Command Injection | `system("ls #{user_input}")` | `system('ls', user_input)` (array form) |

**Auth:** Use Devise with `authenticate_user!`. Check `authorize @record` (Pundit) or `can?` (CanCanCan).

*Full reference: [FULL_RAILS.md](./FULL_RAILS.md)*
