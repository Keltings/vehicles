from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone

# Custom User Model
class CustomUser(AbstractUser):
    ROLE_CHOICES = [
        ('admin', 'Administrator'),
        ('site_manager', 'Site Manager'),
        ('viewer', 'Viewer'),
    ]
    
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='viewer')
    site_name = models.CharField(max_length=200, null=True, blank=True)
    phone_number = models.CharField(max_length=20, blank=True)
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    
    class Meta:
        db_table = 'users'
    
    def __str__(self):
        return f"{self.username} ({self.get_role_display()})"

# Vehicle Model
class Vehicle(models.Model):
    plate_number = models.CharField(max_length=50, db_index=True)
    entry_time = models.DateTimeField(db_index=True)
    exit_time = models.DateTimeField(null=True, blank=True)
    vehicle_type = models.CharField(max_length=50, blank=True)
    plate_color = models.CharField(max_length=50, blank=True)
    vehicle_brand = models.CharField(max_length=100, blank=True)
    amount_paid = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    payment_time = models.DateTimeField(null=True, blank=True)
    payment_method = models.CharField(max_length=50, blank=True)
    site_name = models.CharField(max_length=200, db_index=True)
    file_date = models.CharField(max_length=50, blank=True)
    vehicle_id = models.CharField(max_length=50, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'vehicles'
        ordering = ['-entry_time']
    
    def __str__(self):
        return f"{self.plate_number} - {self.site_name}"

# Audit Log
class AuditLog(models.Model):
    ACTION_CHOICES = [
        ('login', 'User Login'),
        ('logout', 'User Logout'),
        ('view_plate', 'Viewed Plate Number'),
        ('search_vehicle', 'Searched Vehicle'),
        ('export_data', 'Exported Data'),
    ]
    
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    action = models.CharField(max_length=50, choices=ACTION_CHOICES)
    details = models.TextField(blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'audit_logs'
        ordering = ['-timestamp']

# Vehicle Flag/Alert
class VehicleFlag(models.Model):
    REASON_CHOICES = [
        ('suspicious', 'Suspicious Behavior'),
        ('frequent', 'Frequent Visitor'),
        ('overstay', 'Overstay Pattern'),
        ('payment', 'Payment Issue'),
        ('security', 'Security Concern'),
        ('investigation', 'Under Investigation'),
    ]
    
    PRIORITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
    ]
    
    plate_number = models.CharField(max_length=50, db_index=True)
    reason = models.CharField(max_length=50, choices=REASON_CHOICES)
    priority = models.CharField(max_length=20, choices=PRIORITY_CHOICES, default='medium')
    description = models.TextField()
    flagged_by = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True)
    site_name = models.CharField(max_length=200, blank=True)
    is_active = models.BooleanField(default=True)
    alert_on_entry = models.BooleanField(default=True)
    email_recipients = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'vehicle_flags'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.plate_number} - {self.get_reason_display()}"