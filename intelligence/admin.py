from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser, Vehicle, AuditLog, VehicleFlag

@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    list_display = ['username', 'email', 'role', 'is_active']
    list_filter = ['role', 'is_active']
    fieldsets = UserAdmin.fieldsets + (
        ('Custom Fields', {'fields': ('role', 'site_name', 'phone_number')}),
    )

@admin.register(Vehicle)
class VehicleAdmin(admin.ModelAdmin):
    list_display = ['plate_number', 'site_name', 'entry_time', 'vehicle_type']
    list_filter = ['site_name', 'vehicle_type']
    search_fields = ['plate_number']

@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ['user', 'action', 'timestamp']
    list_filter = ['action']

@admin.register(VehicleFlag)
class VehicleFlagAdmin(admin.ModelAdmin):
    list_display = ['plate_number', 'reason', 'priority', 'is_active']
    list_filter = ['priority', 'is_active']