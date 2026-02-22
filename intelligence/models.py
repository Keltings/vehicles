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
    
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, null=True, blank=True)
    action = models.CharField(max_length=50, choices=ACTION_CHOICES)
    details = models.TextField(blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'audit_logs'
        ordering = ['-timestamp']

# Vehicle Flag/Alert
class VehicleFlag(models.Model):
    PRIORITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    RULE_TYPE_CHOICES = [
        ('manual', 'Manual Flag'),
        ('no_exit', 'No Exit Record'),
        ('overstay', 'Overstay (>24h)'),
        ('rapid_movement', 'Rapid Multi-Site Movement'),
        ('frequent_visitor', 'Unusual Visit Frequency'),
        ('payment_issue', 'Payment Discrepancy'),
        ('custom', 'Custom Rule'),
    ]
    
    plate_number = models.CharField(max_length=20)
    reason = models.CharField(max_length=200)
    description = models.TextField(blank=True, null=True)
    priority = models.CharField(max_length=20, choices=PRIORITY_CHOICES, default='medium')
    rule_type = models.CharField(max_length=50, choices=RULE_TYPE_CHOICES, default='manual')
    flagged_by = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, related_name='flags_created')
    flagged_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolved_by = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, blank=True, related_name='flags_resolved')
    resolution_notes = models.TextField(blank=True, null=True)
    email_sent = models.BooleanField(default=False)
    sms_sent = models.BooleanField(default=False)
    
    class Meta:
        db_table = 'vehicle_flags'
        ordering = ['-flagged_at']
    
    def __str__(self):
        return f"{self.plate_number} - {self.reason}"
    
class CustomAlertRule(models.Model):
        CONDITION_CHOICES = [
            ('no_exit', 'Vehicle has no exit record'),
            ('overstay', 'Vehicle overstays (duration > threshold)'),
            ('visit_count', 'Visit frequency exceeds threshold'),
            ('rapid_movement', 'Visits multiple sites rapidly'),
            ('specific_site', 'Vehicle enters specific site'),
            ('time_based', 'Vehicle enters during specific time'),
            ('plate_pattern', 'Plate matches pattern'),
        ]
        
        name = models.CharField(max_length=200)
        description = models.TextField(blank=True, null=True)
        condition_type = models.CharField(max_length=50, choices=CONDITION_CHOICES)
        is_active = models.BooleanField(default=True)
        priority = models.CharField(max_length=20, choices=VehicleFlag.PRIORITY_CHOICES, default='medium')
        
        # Condition parameters (JSON)
        threshold_hours = models.IntegerField(null=True, blank=True)  # For overstay
        threshold_count = models.IntegerField(null=True, blank=True)  # For visit_count
        threshold_sites = models.IntegerField(null=True, blank=True)  # For rapid_movement
        target_site = models.CharField(max_length=100, blank=True, null=True)  # For specific_site
        time_start = models.TimeField(null=True, blank=True)  # For time_based
        time_end = models.TimeField(null=True, blank=True)  # For time_based
        plate_pattern = models.CharField(max_length=50, blank=True, null=True)  # For plate_pattern (regex)
        
        # Notifications
        send_email = models.BooleanField(default=True)
        send_sms = models.BooleanField(default=False)
        email_recipients = models.TextField(blank=True, null=True)  # Comma-separated emails
        sms_recipients = models.TextField(blank=True, null=True)  # Comma-separated phone numbers
        
        created_by = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True)
        created_at = models.DateTimeField(auto_now_add=True)
        last_triggered = models.DateTimeField(null=True, blank=True)
        trigger_count = models.IntegerField(default=0)
        
        class Meta:
            db_table = 'custom_alert_rules'
            ordering = ['-created_at']
        
        def __str__(self):
            return self.name    