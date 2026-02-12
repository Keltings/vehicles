# vehicle_intelligence_app/auth_views.py
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from functools import wraps
from .models import AuditLog


def get_client_ip(request):
    """Get client IP address"""
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        ip = x_forwarded_for.split(",")[0]
    else:
        ip = request.META.get("REMOTE_ADDR")
    return ip


def log_action(action, details=""):
    """Decorator to log user actions"""

    def decorator(view_func):
        @wraps(view_func)
        def wrapped_view(request, *args, **kwargs):
            if request.user.is_authenticated:
                AuditLog.objects.create(
                    user=request.user,
                    action=action,
                    details=details,
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get("HTTP_USER_AGENT", ""),
                )
            return view_func(request, *args, **kwargs)

        return wrapped_view

    return decorator


def role_required(*roles):
    """Decorator to check user role"""

    def decorator(view_func):
        @wraps(view_func)
        def wrapped_view(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect("login")

            if request.user.role not in roles:
                messages.error(
                    request, "You do not have permission to access this page."
                )
                return redirect("dashboard")

            return view_func(request, *args, **kwargs)

        return wrapped_view

    return decorator


def admin_required(view_func):
    """Decorator for admin-only views"""
    return role_required("admin")(view_func)


def site_manager_or_admin(view_func):
    """Decorator for site managers and admins"""
    return role_required("admin", "site_manager")(view_func)


def login_view(request):
    """User login"""
    if request.user.is_authenticated:
        return redirect("dashboard")

    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        user = authenticate(request, username=username, password=password)

        if user is not None:
            if user.is_active:
                login(request, user)

                # Update last login IP
                user.last_login_ip = get_client_ip(request)
                user.save(update_fields=["last_login_ip"])

                # Log action
                AuditLog.objects.create(
                    user=user,
                    action="login",
                    details=f"Successful login",
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get("HTTP_USER_AGENT", ""),
                )

                messages.success(
                    request, f"Welcome back, {user.first_name or user.username}!"
                )

                # Redirect to next page or dashboard
                next_page = request.GET.get("next", "dashboard")
                return redirect(next_page)
            else:
                messages.error(request, "Your account is disabled.")
        else:
            messages.error(request, "Invalid username or password.")

    return render(request, "login.html")


@login_required
def logout_view(request):
    """User logout"""
    # Log action
    AuditLog.objects.create(
        user=request.user,
        action="logout",
        details="User logged out",
        ip_address=get_client_ip(request),
        user_agent=request.META.get("HTTP_USER_AGENT", ""),
    )

    logout(request)
    messages.success(request, "You have been logged out successfully.")
    return redirect("login")
