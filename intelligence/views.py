from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db.models import Count, Max, Q, F, ExpressionWrapper, DurationField,Avg
from django.utils import timezone
from datetime import timedelta, datetime
from .models import CustomUser, Vehicle, VehicleFlag, AuditLog,CustomAlertRule

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            login(request, user)
            user.last_login_ip = get_client_ip(request)
            user.save()
            
            AuditLog.objects.create(
                user=user,
                action='login',
                details='Successful login',
                ip_address=get_client_ip(request)
            )
            
            messages.success(request, f'Welcome back, {user.first_name or user.username}!')
            return redirect('dashboard')
        else:
            messages.error(request, 'Invalid username or password.')
    
    return render(request, 'login.html')

@login_required
def logout_view(request):
    AuditLog.objects.create(
        user=request.user,
        action='logout',
        details='User logged out',
        ip_address=get_client_ip(request)
    )
    logout(request)
    messages.success(request, 'You have been logged out successfully.')
    return redirect('login')

@login_required
def dashboard_view(request):
    from django.utils import timezone
    from datetime import timedelta, datetime
    from django.db.models.functions import TruncDate
    import json
    
    # Get basic stats
    total_vehicles = Vehicle.objects.count()
    active_sites = Vehicle.objects.values('site_name').distinct().count()
    flagged_vehicles = VehicleFlag.objects.filter(is_active=True).count()
    
        # Today's data
    # Get most recent date from data (not today)
    latest_vehicle = Vehicle.objects.order_by('-entry_time').first()

    if latest_vehicle:
        latest_date = latest_vehicle.entry_time.date()
        latest_date_start = timezone.make_aware(
            datetime.combine(latest_date, datetime.min.time())
        )
        latest_date_end = latest_date_start + timedelta(days=1)
        
        todays_entries = Vehicle.objects.filter(
            entry_time__gte=latest_date_start,
            entry_time__lt=latest_date_end
        ).count()
        
        # Previous day
        previous_date_start = latest_date_start - timedelta(days=1)
        previous_date_end = latest_date_start
        
        yesterday_entries = Vehicle.objects.filter(
            entry_time__gte=previous_date_start,
            entry_time__lt=previous_date_end
        ).count()
    else:
        todays_entries = 0
        yesterday_entries = 0
    
    # Vehicles without exit (potential issues)
    no_exit_vehicles = Vehicle.objects.filter(exit_time__isnull=True).count()
    
        # ============================================
    # RECENT ACTIVITIES (Last 10 entries from data)
    # ============================================
    recent_vehicles = Vehicle.objects.order_by('-entry_time')[:5]
    recent_flags = VehicleFlag.objects.filter(is_active=True).order_by('-flagged_at')[:3]
    activities = []

    # Add recent vehicle entries (show actual entry time, not relative)
    for v in recent_vehicles:
        plate_masked = mask_plate_number(v.plate_number)
        
        activities.append({
            'type': 'entry',
            'icon': 'car',
            'text': f'<strong>{plate_masked}</strong> entered {v.site_name}',
            'time': v.entry_time.strftime('%b %d, %Y %H:%M')
        })

    # Add recent alerts (show actual creation time)
    for flag in recent_flags:
        plate_masked = mask_plate_number(flag.plate_number)
        
        activities.append({
            'type': 'alert',
            'icon': 'exclamation-triangle',
            'text': f'<strong>{plate_masked}</strong> flagged - {flag.get_reason_display()}',
            'time': flag.flagged_at.strftime('%b %d, %Y %H:%M')
        })

    # ============================================
    # TRAFFIC CHART (Last 7 days of available data)
    # ============================================
    # Get the most recent date in the data
    latest_entry = Vehicle.objects.order_by('-entry_time').first()

    if latest_entry:
        latest_date = latest_entry.entry_time.date()
        seven_days_before = latest_date - timedelta(days=6)  # 7 days including latest
        
        traffic_data = Vehicle.objects.filter(
            entry_time__date__gte=seven_days_before,
            entry_time__date__lte=latest_date
        ).annotate(
            day=TruncDate('entry_time')
        ).values('day').annotate(
            count=Count('id')
        ).order_by('day')
        
        traffic_chart = []
        for item in traffic_data:
            traffic_chart.append({
                'day': item['day'].strftime('%b %d'),  # Show actual date
                'count': item['count']
            })
    else:
        traffic_chart = []

    # ============================================
    # TOP SITES (From most recent date in data)
    # ============================================
    if latest_entry:
        latest_date_start = timezone.make_aware(
            datetime.combine(latest_entry.entry_time.date(), datetime.min.time())
        )
        latest_date_end = latest_date_start + timedelta(days=1)
        
        site_stats = Vehicle.objects.filter(
            entry_time__gte=latest_date_start,
            entry_time__lt=latest_date_end
        ).values('site_name').annotate(
            entries_today=Count('id')
        ).order_by('-entries_today')[:5]
    else:
        site_stats = []

    top_sites = []
    for site in site_stats:
        # Calculate current occupancy (from that date)
        current_occupancy = Vehicle.objects.filter(
            site_name=site['site_name'],
            entry_time__date=latest_entry.entry_time.date(),
            exit_time__isnull=True
        ).count()
        
        # Calculate average duration for that day
        avg_duration = "N/A"
        site_vehicles = Vehicle.objects.filter(
            site_name=site['site_name'],
            exit_time__isnull=False,
            entry_time__gte=latest_date_start,
            entry_time__lt=latest_date_end
        )
        
        if site_vehicles.exists():
            durations = []
            for v in site_vehicles:
                duration_seconds = (v.exit_time - v.entry_time).total_seconds()
                durations.append(duration_seconds)
            
            avg_seconds = sum(durations) / len(durations)
            avg_hours = int(avg_seconds // 3600)
            avg_minutes = int((avg_seconds % 3600) // 60)
            avg_duration = f"{avg_hours}h {avg_minutes}m"
        
        # Determine status
        status = 'normal'
        if current_occupancy > 300:
            status = 'high'
        
        top_sites.append({
            'site_name': site['site_name'],
            'entries_today': site['entries_today'],
            'current_occupancy': current_occupancy,
            'capacity': 500,
            'avg_duration': avg_duration,
            'status': status
        })
    
    context = {
        'total_vehicles': total_vehicles,
        'active_sites': active_sites,
        'flagged_vehicles': flagged_vehicles,
        'todays_entries': todays_entries,
        'yesterday_entries': yesterday_entries,
        'no_exit_vehicles': no_exit_vehicles,
        'recent_activities': activities,
        'traffic_chart_data': json.dumps(traffic_chart),
        'top_sites': top_sites,
    }
    
    return render(request, 'dashboard.html', context)


def mask_plate_number(plate):
    """Mask middle characters of plate number"""
    if len(plate) <= 5:
        return plate[:2] + '***' + plate[-1:]
    return plate[:3] + '***' + plate[-2:]


# ==========================================
# ANALYTICS VIEWS
# ==========================================

@login_required
def analytics_overview(request):
    """Analytics landing page with module cards"""
    context = {}
    return render(request, 'analytics/overview.html', context)

@login_required
def site_analytics(request):
    """Site comparison analytics"""
    from django.db.models import Count, Avg, F, ExpressionWrapper, DurationField
    
    # Site stats
    site_stats = Vehicle.objects.values('site_name').annotate(
        total_entries=Count('id'),
        unique_vehicles=Count('plate_number', distinct=True),
        avg_duration=Avg(
            ExpressionWrapper(
                F('exit_time') - F('entry_time'),
                output_field=DurationField()
            ),
            filter=Q(exit_time__isnull=False)
        )
    ).order_by('-total_entries')
    
    # Format for display
    formatted_stats = []
    for stat in site_stats:
        avg_hours = 0
        if stat['avg_duration']:
            avg_hours = round(stat['avg_duration'].total_seconds() / 3600, 1)
        
        formatted_stats.append({
            'site_name': stat['site_name'],
            'total_entries': stat['total_entries'],
            'unique_vehicles': stat['unique_vehicles'],
            'avg_duration': avg_hours
        })
    
    context = {
        'site_stats': formatted_stats,
    }
    
    return render(request, 'analytics/site_analytics.html', context)

@login_required
def time_analytics(request):
    """Time-based analytics with filters"""
    from django.db.models.functions import ExtractHour
    from datetime import timedelta
    import json
    
    # Get filter parameters
    date_range = request.GET.get('date_range', '30')  # Default 30 days
    site = request.GET.get('site', '')
    vehicle_type = request.GET.get('vehicle_type', '')
    
    # Base queryset
    qs = Vehicle.objects.filter(entry_time__isnull=False)
    
    # Apply date filter
    if date_range != 'all':
        days = int(date_range)
        cutoff_date = timezone.now() - timedelta(days=days)
        qs = qs.filter(entry_time__gte=cutoff_date)
    
    # Apply site filter
    if site:
        qs = qs.filter(site_name=site)
    
    # Apply vehicle type filter
    if vehicle_type:
        qs = qs.filter(vehicle_type=vehicle_type)
    
    # Get hourly distribution
    hourly_data = qs.annotate(
        hour=ExtractHour('entry_time')
    ).values('hour').annotate(
        count=Count('id')
    ).order_by('hour')
    
    # Convert to list
    hourly_list = []
    for item in hourly_data:
        hourly_list.append({
            'hour': item['hour'],
            'count': item['count']
        })
    
    # Calculate summary stats
    total_entries = qs.count()
    peak_hour = max(hourly_list, key=lambda x: x['count'])['hour'] if hourly_list else 0
    avg_per_hour = total_entries / 24 if total_entries > 0 else 0
    
    # Get all sites and vehicle types for filter dropdowns
    all_sites = Vehicle.objects.values_list('site_name', flat=True).distinct().order_by('site_name')
    all_vehicle_types = Vehicle.objects.values_list('vehicle_type', flat=True).distinct().order_by('vehicle_type')
    
    context = {
        'hourly_data': json.dumps(hourly_list),
        'total_entries': total_entries,
        'peak_hour': peak_hour,
        'avg_per_hour': avg_per_hour,
        'sites': all_sites,
        'vehicle_types': all_vehicle_types,
        'date_range': date_range,
        'site': site,
        'vehicle_type': vehicle_type,
    }
    
    return render(request, 'analytics/time_analytics.html', context)
@login_required
def vehicle_type_analytics(request):
    """Vehicle type distribution with filters"""
    import json
    
    # Get filter
    site = request.GET.get('site', '')
    
    # Base queryset
    qs = Vehicle.objects.all()
    
    # Apply site filter
    if site:
        qs = qs.filter(site_name=site)
    
    # Get type distribution
    type_data = qs.values('vehicle_type').annotate(
        count=Count('id')
    ).order_by('-count')
    
    total = qs.count()
    
    formatted_types = []
    for item in type_data:
        vtype = item['vehicle_type'] or 'Unknown'
        count = item['count']
        percentage = round((count / total) * 100, 1) if total > 0 else 0
        
        formatted_types.append({
            'type': vtype,
            'count': count,
            'percentage': percentage
        })
    
    # Get all sites for filter
    all_sites = Vehicle.objects.values_list('site_name', flat=True).distinct().order_by('site_name')
    
    context = {
        'type_data': formatted_types,
        'type_data_json': json.dumps(formatted_types),
        'total_vehicles': total,
        'sites': all_sites,
        'site': site,
    }
    
    return render(request, 'analytics/vehicle_type_analytics.html', context)
@login_required
def duration_analytics(request):
    """Duration/stay time analytics"""
    from datetime import timedelta
    
    vehicles_with_exit = Vehicle.objects.filter(
        entry_time__isnull=False,
        exit_time__isnull=False
    ).annotate(
        duration_seconds=ExpressionWrapper(
            F('exit_time') - F('entry_time'),
            output_field=DurationField()
        )
    )
    
    # Categorize durations
    total = vehicles_with_exit.count()
    
    under_1h = vehicles_with_exit.filter(duration_seconds__lt=timedelta(hours=1)).count()
    between_1_3h = vehicles_with_exit.filter(
        duration_seconds__gte=timedelta(hours=1),
        duration_seconds__lte=timedelta(hours=3)
    ).count()
    over_3h = vehicles_with_exit.filter(duration_seconds__gt=timedelta(hours=3)).count()
    
    context = {
        'total_analyzed': total,
        'under_1h': under_1h,
        'between_1_3h': between_1_3h,
        'over_3h': over_3h,
        'under_1h_percent': round((under_1h / total) * 100, 1) if total > 0 else 0,
        'between_1_3h_percent': round((between_1_3h / total) * 100, 1) if total > 0 else 0,
        'over_3h_percent': round((over_3h / total) * 100, 1) if total > 0 else 0,
    }
    
    return render(request, 'analytics/duration_analytics.html', context)

# ==========================================
# VEHICLE BEHAVIOR VIEWS
# ==========================================

@login_required
def vehicle_search(request):
    """Search vehicle behavior"""
    plate = request.GET.get('plate', '')
    results = None
    
    if plate:
        results = Vehicle.objects.filter(plate_number__icontains=plate).order_by('-entry_time')[:20]
    
    context = {
        'plate': plate,
        'results': results,
    }
    
    return render(request, 'vehicles/vehicle_search.html', context)

# ==========================================
# ALERTS VIEWS
# ==========================================

@login_required
def alerts_center(request):
    """Enhanced alerts center with graphs, bulk actions, and history"""
    from datetime import timedelta
    import json
    
    # Get active tab
    active_tab = request.GET.get('tab', 'active')
    
    # STATS
    stats = {
        'critical': VehicleFlag.objects.filter(is_active=True, priority='critical').count(),
        'high': VehicleFlag.objects.filter(is_active=True, priority='high').count(),
        'medium': VehicleFlag.objects.filter(is_active=True, priority='medium').count(),
        'low': VehicleFlag.objects.filter(is_active=True, priority='low').count(),
        'resolved_today': VehicleFlag.objects.filter(
            is_active=False,
            resolved_at__date=timezone.now().date()
        ).count(),
    }
    
    # ACTIVE ALERTS (with filters)
    priority_filter = request.GET.get('priority', '')
    rule_type_filter = request.GET.get('rule_type', '')
    
    active_alerts_qs = VehicleFlag.objects.filter(is_active=True).order_by('-flagged_at')
    
    if priority_filter:
        active_alerts_qs = active_alerts_qs.filter(priority=priority_filter)
    
    if rule_type_filter:
        active_alerts_qs = active_alerts_qs.filter(rule_type=rule_type_filter)
    
    active_alerts = []
    for alert in active_alerts_qs[:100]:  # Limit to 100
        active_alerts.append({
            'id': alert.id,
            'plate_number': alert.plate_number,
            'plate_masked': mask_plate_number(alert.plate_number),
            'reason': alert.reason,
            'priority': alert.priority,
            'rule_type': alert.rule_type,
            'get_rule_type_display': alert.get_rule_type_display(),
            'flagged_at': alert.flagged_at,
        })
    
    # RESOLVED ALERTS (history)
    resolved_alerts_qs = VehicleFlag.objects.filter(is_active=False).order_by('-resolved_at')[:50]
    
    resolved_alerts = []
    for alert in resolved_alerts_qs:
        resolved_alerts.append({
            'id': alert.id,
            'plate_number': alert.plate_number,
            'plate_masked': mask_plate_number(alert.plate_number),
            'reason': alert.reason,
            'priority': alert.priority,
            'flagged_at': alert.flagged_at,
            'resolved_at': alert.resolved_at,
            'resolved_by': alert.resolved_by,
        })
    
    # PRIORITY PIE CHART DATA
    priority_chart = [
        {'priority': 'Critical', 'count': stats['critical']},
        {'priority': 'High', 'count': stats['high']},
        {'priority': 'Medium', 'count': stats['medium']},
        {'priority': 'Low', 'count': stats['low']},
    ]
    
    # TRENDS CHART (last 7 days)
    trends_chart = []
    for i in range(6, -1, -1):
        date = timezone.now().date() - timedelta(days=i)
        count = VehicleFlag.objects.filter(
            flagged_at__date=date
        ).count()
        trends_chart.append({
            'date': date.strftime('%b %d'),
            'count': count
        })
    
    # CUSTOM RULES
    custom_rules = CustomAlertRule.objects.all().order_by('-created_at')
    
    # Get all sites for rule creation modal
    all_sites = Vehicle.objects.values_list('site_name', flat=True).distinct().order_by('site_name')
    
    context = {
        'stats': stats,
        'active_alerts': active_alerts,
        'resolved_alerts': resolved_alerts,
        'active_count': len(active_alerts),
        'resolved_count': len(resolved_alerts),
        'rules_count': custom_rules.count(),
        'custom_rules': custom_rules,
        'all_sites': all_sites,}
    
    return render(request, 'alerts/alerts_center.html', context)


@login_required
def create_alert(request):
    """Create a new manual alert"""
    if request.method == 'POST':
        plate_number = request.POST.get('plate_number', '').strip().upper()
        priority = request.POST.get('priority', 'medium')
        reason = request.POST.get('reason', '')
        description = request.POST.get('description', '')
        send_email = request.POST.get('send_email') == '1'
        
        # Create the alert
        alert = VehicleFlag.objects.create(
            plate_number=plate_number,
            priority=priority,
            reason=reason,
            description=description,
            rule_type='manual',
            flagged_by=request.user,
            email_sent=False,  # Will be updated after sending
        )
        
        # Send email notification if requested
        if send_email:
            try:
                send_alert_email(alert, request.user)
                alert.email_sent = True
                alert.save()
            except Exception as e:
                print(f"Error sending email: {e}")
        
        # Create audit log
        AuditLog.objects.create(
            user=request.user,
            action='create_alert',
            details=f'Created alert for {plate_number}: {reason}',
            ip_address=get_client_ip(request)
        )
        
        messages.success(request, f'Alert created for {plate_number}')
        return redirect('alerts_center')
    
    return redirect('alerts_center')


@login_required
def resolve_alert_api(request, alert_id):
    """API endpoint to resolve a single alert"""
    from django.http import JsonResponse
    import json
    
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            notes = data.get('notes', '')
            
            alert = VehicleFlag.objects.get(id=alert_id)
            alert.is_active = False
            alert.resolved_at = timezone.now()
            alert.resolved_by = request.user
            alert.resolution_notes = notes
            alert.save()
            
            # Create audit log
            AuditLog.objects.create(
                user=request.user,
                action='resolve_alert',
                details=f'Resolved alert for {alert.plate_number}: {alert.reason}',
                ip_address=get_client_ip(request)
            )
            
            return JsonResponse({'success': True})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=400)
    
    return JsonResponse({'success': False}, status=400)


@login_required
def bulk_resolve_alerts(request):
    """Bulk resolve multiple alerts"""
    from django.http import JsonResponse
    import json
    
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            ids = data.get('ids', [])
            
            alerts = VehicleFlag.objects.filter(id__in=ids, is_active=True)
            count = alerts.count()
            
            alerts.update(
                is_active=False,
                resolved_at=timezone.now(),
                resolved_by=request.user,
                resolution_notes='Bulk resolved'
            )
            
            # Create audit log
            AuditLog.objects.create(
                user=request.user,
                action='bulk_resolve_alerts',
                details=f'Bulk resolved {count} alerts',
                ip_address=get_client_ip(request)
            )
            
            return JsonResponse({'success': True, 'count': count})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=400)
    
    return JsonResponse({'success': False}, status=400)


@login_required
def bulk_delete_alerts(request):
    """Bulk delete multiple alerts"""
    from django.http import JsonResponse
    import json
    
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            ids = data.get('ids', [])
            
            count = VehicleFlag.objects.filter(id__in=ids).count()
            VehicleFlag.objects.filter(id__in=ids).delete()
            
            # Create audit log
            AuditLog.objects.create(
                user=request.user,
                action='bulk_delete_alerts',
                details=f'Bulk deleted {count} alerts',
                ip_address=get_client_ip(request)
            )
            
            return JsonResponse({'success': True, 'count': count})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=400)
    
    return JsonResponse({'success': False}, status=400)


def send_alert_email(alert, user):
    """Send email notification for alert"""
    from django.core.mail import send_mail
    from django.conf import settings
    
    subject = f'[{alert.priority.upper()}] Vehicle Alert: {alert.plate_number}'
    
    message = f"""
    New vehicle alert created:
    
    Plate Number: {alert.plate_number}
    Priority: {alert.priority.upper()}
    Reason: {alert.reason}
    Description: {alert.description or 'N/A'}
    
    Flagged by: {user.username}
    Time: {alert.flagged_at.strftime('%Y-%m-%d %H:%M:%S')}
    
    Please review this alert in the system.
    """
    
    # You need to configure email settings in settings.py
    try:
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [user.email],  # Send to the user who created it (or configure recipient list)
            fail_silently=False,
        )
    except Exception as e:
        print(f"Email send error: {e}")
        raise

@login_required
def watchlist(request):
    """Watchlist management"""
    
    # Handle form submission
    if request.method == 'POST':
        plate_number = request.POST.get('plate_number', '').strip().upper()
        reason = request.POST.get('reason')
        priority = request.POST.get('priority')
        description = request.POST.get('description')
        alert_on_entry = request.POST.get('alert_on_entry') == 'on'
        
        # VALIDATION: Check if vehicle exists in database
        vehicle_exists = Vehicle.objects.filter(plate_number__iexact=plate_number).exists()
        
        if not vehicle_exists:
            messages.error(request, f'Vehicle {plate_number} not found in database. Please verify the plate number.')
            return redirect('watchlist')
        
        # Check if already flagged
        already_flagged = VehicleFlag.objects.filter(
            plate_number__iexact=plate_number,
            is_active=True
        ).exists()
        
        if already_flagged:
            messages.warning(request, f'Vehicle {plate_number} is already on the watchlist.')
            return redirect('watchlist')
        
        # Create the flag
        VehicleFlag.objects.create(
            plate_number=plate_number,
            reason=reason,
            priority=priority,
            description=description,
            flagged_by=request.user,
            alert_on_entry=alert_on_entry,
            is_active=True
        )
        
        # Log the action
        AuditLog.objects.create(
            user=request.user,
            action='view_plate',
            details=f'Added {plate_number} to watchlist - Reason: {reason}',
            ip_address=get_client_ip(request)
        )
        
        messages.success(request, f'Vehicle {plate_number} added to watchlist successfully!')
        return redirect('watchlist')
    
    # Get flagged vehicles
    flagged = VehicleFlag.objects.filter(is_active=True).order_by('-flagged_at')
    
    # Get recent unique plates for autocomplete (last 100)
    recent_plates = Vehicle.objects.values_list('plate_number', flat=True).distinct().order_by('-entry_time')[:100]

    context = {
        'flagged_vehicles': flagged,
        'recent_plates': recent_plates,
}
    
    return render(request, 'alerts/watchlist.html', context)

@login_required
def vehicle_detail_api(request, plate_number):
    """API endpoint to get full vehicle details with audit logging"""
    from django.http import JsonResponse
    
    # LOG THE PROFILE VIEW
    AuditLog.objects.create(
        user=request.user,
        action='view_vehicle_profile',
        details=f'Viewed profile for: {plate_number}',
        ip_address=get_client_ip(request)
    )
    
    # Get all visits for this vehicle
    vehicles = Vehicle.objects.filter(plate_number__iexact=plate_number).order_by('entry_time')
    
    if not vehicles.exists():
        return JsonResponse({'error': 'Vehicle not found'}, status=404)
    
    first_vehicle = vehicles.first()
    latest_vehicle = vehicles.latest('entry_time')
    
    # Calculate stats
    total_visits = vehicles.count()
    sites_visited = vehicles.values('site_name').distinct().count()
    
    # Most frequent site
    most_frequent = vehicles.values('site_name').annotate(
        count=Count('id')
    ).order_by('-count').first()
    
    most_frequent_site = most_frequent['site_name'] if most_frequent else 'N/A'
    
    # Average duration
    vehicles_with_duration = vehicles.filter(exit_time__isnull=False).annotate(
        duration=ExpressionWrapper(
            F('exit_time') - F('entry_time'),
            output_field=DurationField()
        )
    )
    
    avg_duration = 'N/A'
    if vehicles_with_duration.exists():
        avg_dur = vehicles_with_duration.aggregate(avg=Avg('duration'))['avg']
        if avg_dur:
            hours = int(avg_dur.total_seconds() // 3600)
            minutes = int((avg_dur.total_seconds() % 3600) // 60)
            avg_duration = f"{hours}h {minutes}m"
    
    # Check if flagged
    is_flagged = VehicleFlag.objects.filter(plate_number__iexact=plate_number, is_active=True).exists()
    flag_info = {}
    
    if is_flagged:
        flag = VehicleFlag.objects.filter(plate_number__iexact=plate_number, is_active=True).first()
        flag_info = {
            'reason': flag.reason,
            'priority': flag.priority,
            'description': flag.description or 'N/A',
        }
    
    # Get COMPLETE visit history (all visits, not just 10)
    visit_history = []
    for v in vehicles:  # ALL visits, chronological order
        duration = None
        if v.exit_time and v.entry_time:
            duration_seconds = (v.exit_time - v.entry_time).total_seconds()
            hours = int(duration_seconds // 3600)
            minutes = int((duration_seconds % 3600) // 60)
            duration = f"{hours}h {minutes}m"
        
        visit_history.append({
            'site': v.site_name,
            'entry': v.entry_time.strftime('%b %d, %Y %H:%M'),
            'exit': v.exit_time.strftime('%b %d, %Y %H:%M') if v.exit_time else 'Still inside',
            'duration': duration or 'N/A',
            'amount_paid': float(v.amount_paid) if v.amount_paid else 0,
            'payment_method': v.payment_method or 'N/A',
            'vehicle_color': v.plate_color or 'Unknown',
            'vehicle_brand': v.vehicle_brand or 'Unknown',
        })
    
    data = {
        'plate_number': plate_number,
        'vehicle_type': first_vehicle.vehicle_type or 'Unknown',
        'vehicle_brand': first_vehicle.vehicle_brand or 'Unknown',
        'plate_color': first_vehicle.plate_color or 'Unknown',
        'first_seen': first_vehicle.entry_time.strftime('%b %d, %Y'),
        'last_seen': latest_vehicle.entry_time.strftime('%b %d, %Y'),
        'total_visits': total_visits,
        'sites_visited': sites_visited,
        'most_frequent_site': most_frequent_site,
        'avg_duration': avg_duration,
        'is_flagged': is_flagged,
        'flag_info': flag_info,
        'visit_history': visit_history,
    }
    
    return JsonResponse(data)

@login_required
def resolve_alert(request, flag_id):
    """Mark alert as resolved"""
    if request.method == 'POST':
        try:
            flag = VehicleFlag.objects.get(id=flag_id, is_active=True)
            flag.is_active = False
            flag.resolved_at = timezone.now()
            flag.save()
            
            # Log the action
            AuditLog.objects.create(
                user=request.user,
                action='view_plate',
                details=f'Resolved alert for {flag.plate_number}',
                ip_address=get_client_ip(request)
            )
            
            messages.success(request, f'Alert for {flag.plate_number} marked as resolved.')
        except VehicleFlag.DoesNotExist:
            messages.error(request, 'Alert not found.')
    
    return redirect('alerts_center')

@login_required
def remove_from_watchlist(request, flag_id):
    """Remove vehicle from watchlist"""
    if request.method == 'POST':
        try:
            flag = VehicleFlag.objects.get(id=flag_id)
            plate = flag.plate_number
            flag.delete()
            
            # Log the action
            AuditLog.objects.create(
                user=request.user,
                action='view_plate',
                details=f'Removed {plate} from watchlist',
                ip_address=get_client_ip(request)
            )
            
            messages.success(request, f'Vehicle {plate} removed from watchlist.')
        except VehicleFlag.DoesNotExist:
            messages.error(request, 'Vehicle not found in watchlist.')
    
    return redirect('watchlist')
@login_required
def analytics_overview(request):
    """Comprehensive analytics overview with tables and operational insights"""
    from django.db.models.functions import ExtractHour, TruncDate
    from datetime import timedelta
    from collections import defaultdict
    import json
    
    # Get filters
    date_range = request.GET.get('date_range', '30')
    selected_site = request.GET.get('site', '')
    selected_vehicle_type = request.GET.get('vehicle_type', '')
    
    # Get date range
    latest_vehicle = Vehicle.objects.order_by('-entry_time').first()
    
    if not latest_vehicle:
        return render(request, 'analytics/analytics_overview.html', {
            'unique_vehicles': 0,
            'cross_site_movements': 0,
            'avg_dwell_time': '0h 0m',
            'anomalies': 0,
            'site_performance': [],
            'peak_hours': [],
            'payment_methods': [],
            'vehicle_distribution': [],
            'frequent_routes': [],
            'operational_issues': [],
        })
    
    end_date = latest_vehicle.entry_time.date()
    
    if date_range == 'all':
        start_date = Vehicle.objects.order_by('entry_time').first().entry_time.date()
        days = (end_date - start_date).days
    else:
        days = int(date_range)
        start_date = end_date - timedelta(days=days)
    
    start_datetime = timezone.make_aware(datetime.combine(start_date, datetime.min.time()))
    end_datetime = timezone.make_aware(datetime.combine(end_date, datetime.max.time()))
    
    # Base queryset with filters
    base_qs = Vehicle.objects.filter(
        entry_time__gte=start_datetime,
        entry_time__lte=end_datetime
    )
    
    if selected_site:
        base_qs = base_qs.filter(site_name=selected_site)
    
    if selected_vehicle_type:
        base_qs = base_qs.filter(vehicle_type=selected_vehicle_type)
        
        # ============================================
    # SUMMARY STATS (Context-aware based on filters)
    # ============================================
    unique_vehicles = base_qs.values('plate_number').distinct().count()

    # Cross-site movements (if site selected, show vehicles that visited this site + others)
    if selected_site:
        # Get vehicles that visited the selected site
        vehicles_at_site = base_qs.filter(site_name=selected_site).values_list('plate_number', flat=True).distinct()
        
        # For each vehicle, check if they visited other sites too
        cross_site_movements = 0
        for plate in vehicles_at_site:
            sites_visited = Vehicle.objects.filter(
                plate_number=plate,
                entry_time__gte=start_datetime,
                entry_time__lte=end_datetime
            ).values('site_name').distinct().count()
            
            if sites_visited > 1:
                cross_site_movements += 1
        
        cross_site_percentage = (cross_site_movements / len(vehicles_at_site) * 100) if vehicles_at_site else 0
    else:
        # All sites - show vehicles that visited multiple sites
        vehicle_site_counts = base_qs.values('plate_number').annotate(
            site_count=Count('site_name', distinct=True)
        )
        cross_site_movements = sum(1 for v in vehicle_site_counts if v['site_count'] > 1)
        cross_site_percentage = (cross_site_movements / unique_vehicles * 100) if unique_vehicles > 0 else 0

    # Average dwell time (context message)
    vehicles_with_duration = base_qs.filter(exit_time__isnull=False).annotate(
        duration=ExpressionWrapper(
            F('exit_time') - F('entry_time'),
            output_field=DurationField()
        )
    )

    avg_dwell_time = '0h 0m'
    dwell_context = 'No data available'

    if vehicles_with_duration.exists():
        avg_duration_obj = vehicles_with_duration.aggregate(avg=Avg('duration'))['avg']
        if avg_duration_obj:
            avg_hours = int(avg_duration_obj.total_seconds() // 3600)
            avg_minutes = int((avg_duration_obj.total_seconds() % 3600) // 60)
            avg_dwell_time = f"{avg_hours}h {avg_minutes}m"
            
            # Context message based on filters
            if selected_site:
                dwell_context = f'At {selected_site}'
            else:
                dwell_context = 'Across all sites'

    # Operational issues
    anomalies = base_qs.filter(
        Q(exit_time__isnull=True) |
        Q(exit_time__gt=F('entry_time') + timedelta(hours=24))
    ).count()

    # Context messages for cards
    unique_vehicles_context = f'Last {days} days'
    if selected_site:
        unique_vehicles_context = f'At {selected_site}'

    cross_site_context = f'{cross_site_percentage:.1f}% of total'

    anomaly_context = 'Requires attention' if anomalies > 0 else 'All clear'
    anomaly_color = 'danger' if anomalies > 0 else 'success'
    
    # Average dwell time
    vehicles_with_duration = base_qs.filter(exit_time__isnull=False).annotate(
        duration=ExpressionWrapper(
            F('exit_time') - F('entry_time'),
            output_field=DurationField()
        )
    )
    
    avg_dwell_time = '0h 0m'
    if vehicles_with_duration.exists():
        avg_duration_obj = vehicles_with_duration.aggregate(avg=Avg('duration'))['avg']
        if avg_duration_obj:
            avg_hours = int(avg_duration_obj.total_seconds() // 3600)
            avg_minutes = int((avg_duration_obj.total_seconds() % 3600) // 60)
            avg_dwell_time = f"{avg_hours}h {avg_minutes}m"
    
    # Operational issues
    anomalies = base_qs.filter(
        Q(exit_time__isnull=True) |
        Q(exit_time__gt=F('entry_time') + timedelta(hours=24))
    ).count()
    
    # ============================================
    # SITE PERFORMANCE TABLE
    # ============================================
    site_stats = base_qs.values('site_name').annotate(
        total_entries=Count('id'),
        unique_vehicles=Count('plate_number', distinct=True)
    ).order_by('-total_entries')
    
    site_performance = []
    for site in site_stats:
        # Calculate average duration for this site
        site_vehicles = base_qs.filter(
            site_name=site['site_name'],
            exit_time__isnull=False
        ).annotate(
            duration=ExpressionWrapper(
                F('exit_time') - F('entry_time'),
                output_field=DurationField()
            )
        )
        
        avg_duration = "N/A"
        if site_vehicles.exists():
            avg_dur = site_vehicles.aggregate(avg=Avg('duration'))['avg']
            if avg_dur:
                hrs = int(avg_dur.total_seconds() // 3600)
                mins = int((avg_dur.total_seconds() % 3600) // 60)
                avg_duration = f"{hrs}h {mins}m"
        
        # Current occupancy
        current_occupancy = base_qs.filter(
            site_name=site['site_name'],
            exit_time__isnull=True
        ).count()
        
        # Utilization (assume capacity of 500 for now)
        capacity = 500
        utilization = int((current_occupancy / capacity) * 100) if capacity > 0 else 0
        
        # Status
        if utilization > 80:
            status = 'danger'
        elif utilization > 60:
            status = 'warning'
        else:
            status = 'success'
        
        site_performance.append({
            'site_name': site['site_name'],
            'total_entries': site['total_entries'],
            'unique_vehicles': site['unique_vehicles'],
            'avg_duration': avg_duration,
            'current_occupancy': current_occupancy,
            'utilization': utilization,
            'status': status
        })
    
    # ============================================
    # PEAK HOURS TABLE
    # ============================================
    hourly_data = base_qs.annotate(
        hour=ExtractHour('entry_time'),
        day=TruncDate('entry_time')
    ).values('hour').annotate(
        total_count=Count('id'),
        days_count=Count('day', distinct=True)
    ).order_by('-total_count')[:10]
    
    peak_hours = []
    for h in hourly_data:
        avg_count = h['total_count'] // h['days_count'] if h['days_count'] > 0 else h['total_count']
        
        # Find peak day for this hour
        peak_day_data = base_qs.filter(
            entry_time__hour=h['hour']
        ).annotate(
            day=TruncDate('entry_time')
        ).values('day').annotate(
            count=Count('id')
        ).order_by('-count').first()
        
        peak_day = peak_day_data['day'].strftime('%A') if peak_day_data else 'N/A'
        
        peak_hours.append({
            'hour': h['hour'],
            'avg_count': avg_count,
            'peak_day': peak_day
        })
    
    # ============================================
    # PAYMENT METHODS TABLE
    # ============================================
    payment_stats = base_qs.exclude(
        Q(payment_method__isnull=True) | Q(payment_method='')
    ).values('payment_method').annotate(
        count=Count('id')
    ).order_by('-count')
    
    total_payments = sum(p['count'] for p in payment_stats)
    
    payment_methods = []
    payment_methods_chart = []
    for p in payment_stats:
        percentage = (p['count'] / total_payments * 100) if total_payments > 0 else 0
        payment_methods.append({
            'method': p['payment_method'],
            'count': p['count'],
            'percentage': percentage
        })
        payment_methods_chart.append({
            'method': p['payment_method'],
            'count': p['count']
        })
    
    # ============================================
    # VEHICLE TYPE DISTRIBUTION TABLE
    # ============================================
    type_stats = base_qs.values('vehicle_type').annotate(
        count=Count('id')
    ).order_by('-count')
    
    total_vehicles = sum(t['count'] for t in type_stats)
    
    vehicle_distribution = []
    vehicle_type_chart = []
    
    for t in type_stats:
        vtype = t['vehicle_type'] or 'Unknown'
        percentage = (t['count'] / total_vehicles * 100) if total_vehicles > 0 else 0
        
        # Calculate avg duration for this type
        type_vehicles = base_qs.filter(
            vehicle_type=t['vehicle_type'],
            exit_time__isnull=False
        ).annotate(
            duration=ExpressionWrapper(
                F('exit_time') - F('entry_time'),
                output_field=DurationField()
            )
        )
        
        avg_duration = "N/A"
        if type_vehicles.exists():
            avg_dur = type_vehicles.aggregate(avg=Avg('duration'))['avg']
            if avg_dur:
                hrs = int(avg_dur.total_seconds() // 3600)
                mins = int((avg_dur.total_seconds() % 3600) // 60)
                avg_duration = f"{hrs}h {mins}m"
        
        vehicle_distribution.append({
            'type': vtype,
            'count': t['count'],
            'percentage': percentage,
            'avg_duration': avg_duration
        })
        
        vehicle_type_chart.append({
            'type': vtype,
            'count': t['count']
        })
    
    # ============================================
    # FREQUENT ROUTES TABLE
    # ============================================
    # Get vehicles that visited multiple sites
    multi_site_vehicles = base_qs.values('plate_number').annotate(
        site_count=Count('site_name', distinct=True)
    ).filter(site_count__gt=1).values_list('plate_number', flat=True)
    
    routes = defaultdict(lambda: {'unique_vehicles': set(), 'total_trips': 0, 'time_diffs': []})
    
    for plate in multi_site_vehicles[:1000]:  # Limit to 1000 for performance
        visits = base_qs.filter(plate_number=plate).order_by('entry_time')
        
        prev_visit = None
        for visit in visits:
            if prev_visit:
                route_key = f"{prev_visit.site_name} → {visit.site_name}"
                routes[route_key]['unique_vehicles'].add(plate)
                routes[route_key]['total_trips'] += 1
                
                # Calculate time between sites
                time_diff = (visit.entry_time - prev_visit.entry_time).total_seconds()
                routes[route_key]['time_diffs'].append(time_diff)
            
            prev_visit = visit
    
    frequent_routes = []
    for route_key, data in sorted(routes.items(), key=lambda x: len(x[1]['unique_vehicles']), reverse=True)[:10]:
        avg_time = sum(data['time_diffs']) / len(data['time_diffs']) if data['time_diffs'] else 0
        avg_hours = int(avg_time // 3600)
        avg_minutes = int((avg_time % 3600) // 60)
        
        from_site, to_site = route_key.split(' → ')
        
        frequent_routes.append({
            'from_site': from_site,
            'to_site': to_site,
            'unique_vehicles': len(data['unique_vehicles']),
            'total_trips': data['total_trips'],
            'avg_time_between': f"{avg_hours}h {avg_minutes}m"
        })
    
        # ============================================
    # OPERATIONAL ISSUES TABLE (with pagination)
    # ============================================
    operational_issues_all = []

    # No exit records
    no_exit = base_qs.filter(exit_time__isnull=True).order_by('-entry_time')
    for v in no_exit:
        duration = timezone.now() - v.entry_time
        duration_hours = int(duration.total_seconds() // 3600)
        
        operational_issues_all.append({
            'type': 'No Exit',
            'severity': 'warning' if duration_hours < 24 else 'danger',
            'plate': mask_plate_number(v.plate_number),
            'plate_full': v.plate_number,
            'site': v.site_name,
            'entry_time': v.entry_time.strftime('%b %d, %Y %H:%M'),
            'duration': f"{duration_hours}h ago"
        })

    # Overstays (>24 hours)
    overstays = base_qs.filter(
        exit_time__isnull=False,
        exit_time__gt=F('entry_time') + timedelta(hours=24)
    ).order_by('-entry_time')

    for v in overstays:
        duration = (v.exit_time - v.entry_time).total_seconds()
        duration_hours = int(duration // 3600)
        
        operational_issues_all.append({
            'type': 'Overstay',
            'severity': 'danger',
            'plate': mask_plate_number(v.plate_number),
            'plate_full': v.plate_number,
            'site': v.site_name,
            'entry_time': v.entry_time.strftime('%b %d, %Y %H:%M'),
            'duration': f"{duration_hours}h total"
        })

    # Pagination for operational issues (5 per page)
    issues_page = int(request.GET.get('issues_page', 1))
    issues_per_page = 5
    total_issues = len(operational_issues_all)
    total_pages = (total_issues + issues_per_page - 1) // issues_per_page

    start_idx = (issues_page - 1) * issues_per_page
    end_idx = start_idx + issues_per_page
    operational_issues_page = operational_issues_all[start_idx:end_idx]
    
    # ============================================
    # INSIGHTS
    # ============================================
    insights = []
    
    # Peak site insight
    if site_performance:
        busiest = site_performance[0]
        insights.append(f"{busiest['site_name']} is the busiest site with {busiest['total_entries']} entries")
    
    # Cross-site insight
    if cross_site_percentage > 20:
        insights.append(f"{cross_site_percentage:.1f}% of vehicles visit multiple sites - consider multi-site passes")
    
    # Payment method insight
    if payment_methods:
        top_method = payment_methods[0]
        insights.append(f"{top_method['method']} is the preferred payment method ({top_method['percentage']:.1f}%)")
    
    # Get all sites and vehicle types for filters
    all_sites = Vehicle.objects.values_list('site_name', flat=True).distinct().order_by('site_name')
    vehicle_types = Vehicle.objects.exclude(
        Q(vehicle_type__isnull=True) | Q(vehicle_type='')
    ).values_list('vehicle_type', flat=True).distinct().order_by('vehicle_type')
    # Dynamic title for frequent routes
    if date_range == 'all':
        routes_title = 'Most Frequent Routes (All Time)'
    elif date_range == '7':
        routes_title = 'Most Frequent Routes (Last 7 Days)'
    elif date_range == '90':
        routes_title = 'Most Frequent Routes (Last 90 Days)'
    else:
        routes_title = f'Most Frequent Routes (Last {days} Days)'

    if selected_site:
        routes_title += f' - From/To {selected_site}'
    context = {
        'unique_vehicles': unique_vehicles,
        'unique_vehicles_context': unique_vehicles_context,
        'cross_site_movements': cross_site_movements,
        'cross_site_context': cross_site_context,
        'avg_dwell_time': avg_dwell_time,
        'dwell_context': dwell_context,
        'anomalies': anomalies,
        'anomaly_context': anomaly_context,
        'anomaly_color': anomaly_color,
        'days': days,
        'date_range': date_range,
        'selected_site': selected_site,
        'selected_vehicle_type': selected_vehicle_type,
        'site_performance': site_performance,
        'peak_hours': peak_hours,
        'payment_methods_chart': json.dumps(payment_methods_chart),
        'vehicle_distribution': vehicle_distribution,
        'vehicle_type_chart': json.dumps(vehicle_type_chart),
        'frequent_routes': frequent_routes,
        'operational_issues_page': operational_issues_page,
        'current_page': issues_page,
        'total_pages': total_pages,
        'total_issues': total_issues,
        'insights': insights,
        'all_sites': all_sites,
        'vehicle_types': vehicle_types,
        'active_alerts_count': VehicleFlag.objects.filter(is_active=True).count(),
        'routes_title': routes_title,
    }
    return render(request, 'analytics/analytics_overview.html', context)

@login_required
def route_vehicles_api(request):
    """API endpoint to get vehicles that traveled a specific route"""
    from django.http import JsonResponse
    
    from_site = request.GET.get('from', '')
    to_site = request.GET.get('to', '')
    
    if not from_site or not to_site:
        return JsonResponse({'error': 'Missing parameters'}, status=400)
    
    # Get all vehicles and track their journeys
    vehicles_on_route = {}
    
    # Get all vehicles that visited both sites
    plates_at_from = Vehicle.objects.filter(site_name=from_site).values_list('plate_number', flat=True).distinct()
    plates_at_to = Vehicle.objects.filter(site_name=to_site).values_list('plate_number', flat=True).distinct()
    
    # Find common plates
    common_plates = set(plates_at_from) & set(plates_at_to)
    
    for plate in common_plates:
        # Get all visits for this vehicle
        visits = Vehicle.objects.filter(plate_number=plate).order_by('entry_time')
        
        trip_count = 0
        time_diffs = []
        last_trip = None
        vehicle_type = None
        
        prev_visit = None
        for visit in visits:
            if not vehicle_type:
                vehicle_type = visit.vehicle_type or 'Unknown'
            
            if prev_visit and prev_visit.site_name == from_site and visit.site_name == to_site:
                trip_count += 1
                time_diff = (visit.entry_time - prev_visit.entry_time).total_seconds()
                time_diffs.append(time_diff)
                last_trip = visit.entry_time
            
            prev_visit = visit
        
        if trip_count > 0:
            avg_time = sum(time_diffs) / len(time_diffs) if time_diffs else 0
            avg_hours = int(avg_time // 3600)
            avg_minutes = int((avg_time % 3600) // 60)
            
            vehicles_on_route[plate] = {
                'plate': mask_plate_number(plate),
                'plate_full': plate,
                'vehicle_type': vehicle_type,
                'trip_count': trip_count,
                'last_trip': last_trip.strftime('%b %d, %Y %H:%M') if last_trip else 'N/A',
                'avg_time': f"{avg_hours}h {avg_minutes}m"
            }
    
    # Sort by trip count
    vehicles_list = sorted(vehicles_on_route.values(), key=lambda x: x['trip_count'], reverse=True)
    
    return JsonResponse({
        'vehicles': vehicles_list,
        'total': len(vehicles_list)
    })
    
    
@login_required
def audit_plate_view(request):
    """Log when a user views a full plate number"""
    import json
    from django.http import JsonResponse
    from django.views.decorators.csrf import csrf_exempt
    
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            plate_number = data.get('plate_number')
            source = data.get('source', 'Unknown')
            
            # Create audit log
            AuditLog.objects.create(
                user=request.user,
                action='view_plate',
                details=f'Viewed full plate: {plate_number} from {source}',
                ip_address=get_client_ip(request)
            )
            
            return JsonResponse({'success': True})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=400)
    
    return JsonResponse({'success': False, 'error': 'Invalid request'}, status=400)    

@login_required
def export_site_performance(request):
    """Export site performance to CSV"""
    import csv
    from django.http import HttpResponse
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="site_performance.csv"'
    
    writer = csv.writer(response)
    writer.writerow(['Site Name', 'Total Entries', 'Unique Vehicles', 'Avg Duration', 'Current Occupancy'])
    
    # Get same data as analytics page
    sites = Vehicle.objects.values('site_name').annotate(
        total_entries=Count('id'),
        unique_vehicles=Count('plate_number', distinct=True)
    ).order_by('-total_entries')
    
    for site in sites:
        writer.writerow([
            site['site_name'],
            site['total_entries'],
            site['unique_vehicles'],
            'N/A',  # You can calculate this
            'N/A'   # You can calculate this
        ])
    
    return response


@login_required
def export_vehicle_types(request):
    """Export vehicle type distribution to CSV"""
    import csv
    from django.http import HttpResponse
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="vehicle_types.csv"'
    
    writer = csv.writer(response)
    writer.writerow(['Vehicle Type', 'Count', 'Percentage'])
    
    type_stats = Vehicle.objects.values('vehicle_type').annotate(
        count=Count('id')
    ).order_by('-count')
    
    total = sum(t['count'] for t in type_stats)
    
    for t in type_stats:
        percentage = (t['count'] / total * 100) if total > 0 else 0
        writer.writerow([
            t['vehicle_type'] or 'Unknown',
            t['count'],
            f"{percentage:.1f}%"
        ])
    
    return response


@login_required
def export_operational_issues(request):
    """Export operational issues to CSV"""
    import csv
    from django.http import HttpResponse
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="operational_issues.csv"'
    
    writer = csv.writer(response)
    writer.writerow(['Issue Type', 'Plate Number', 'Site', 'Entry Time', 'Duration'])
    
    # Get no-exit vehicles
    no_exit = Vehicle.objects.filter(exit_time__isnull=True).order_by('-entry_time')
    
    for v in no_exit:
        duration = timezone.now() - v.entry_time
        duration_hours = int(duration.total_seconds() // 3600)
        
        writer.writerow([
            'No Exit',
            v.plate_number,  # Full plate in CSV
            v.site_name,
            v.entry_time.strftime('%Y-%m-%d %H:%M'),
            f"{duration_hours}h ago"
        ])
    
    return response

@login_required
def audit_logs_view(request):
    """View audit logs with filters and pagination"""
    from datetime import datetime, timedelta
    
    # Get filters
    selected_user = request.GET.get('user', '')
    selected_action = request.GET.get('action', '')
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')
    search_query = request.GET.get('search', '')
    page = int(request.GET.get('page', 1))
    
    # Base queryset
    logs_qs = AuditLog.objects.all().order_by('-timestamp')
    
    # Apply filters
    if selected_user:
        logs_qs = logs_qs.filter(user_id=selected_user)
    
    if selected_action:
        logs_qs = logs_qs.filter(action=selected_action)
    
    if search_query:
        logs_qs = logs_qs.filter(details__icontains=search_query)
    
    if date_from:
        date_from_obj = datetime.strptime(date_from, '%Y-%m-%d')
        logs_qs = logs_qs.filter(timestamp__gte=date_from_obj)
    
    if date_to:
        date_to_obj = datetime.strptime(date_to, '%Y-%m-%d')
        date_to_obj = date_to_obj.replace(hour=23, minute=59, second=59)
        logs_qs = logs_qs.filter(timestamp__lte=date_to_obj)
    
    # Stats
    total_logs = logs_qs.count()
    plate_views = logs_qs.filter(action='view_plate').count()
    searches = logs_qs.filter(action__icontains='search').count()
    unique_users = logs_qs.values('user').distinct().count()
    
    today_start = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
    today_logs = AuditLog.objects.filter(timestamp__gte=today_start).count()
    
    # Pagination (20 per page)
    per_page = 20
    total_pages = (total_logs + per_page - 1) // per_page
    
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    logs = list(logs_qs[start_idx:end_idx])
    
    # Get all users for filter
    all_users = CustomUser.objects.all().order_by('username')
    
    context = {
        'logs': logs,
        'total_logs': total_logs,
        'plate_views': plate_views,
        'searches': searches,
        'unique_users': unique_users,
        'today_logs': today_logs,
        'all_users': all_users,
        'selected_user': selected_user,
        'selected_action': selected_action,
        'search_query': search_query,
        'date_from': date_from,
        'date_to': date_to,
        'current_page': page,
        'total_pages': total_pages,
    }
    
    return render(request, 'audit_logs.html', context)


@login_required
def export_audit_logs(request):
    """Export audit logs to CSV"""
    import csv
    from django.http import HttpResponse
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="audit_logs.csv"'
    
    writer = csv.writer(response)
    writer.writerow(['Timestamp', 'User', 'Action', 'Details', 'IP Address'])
    
    logs = AuditLog.objects.all().order_by('-timestamp')
    
    for log in logs:
        writer.writerow([
            log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            log.user.username,
            log.action,
            log.details,
            log.ip_address
        ])
    
    return response

@login_required
def vehicle_list(request):
    """Vehicle profiles page with search and browse functionality"""
    from datetime import timedelta
    from django.db.models import Max
    
    # Determine active tab
    active_tab = request.GET.get('tab', 'search')
    
    # SEARCH TAB
    search_plate = request.GET.get('plate', '').strip().upper()
    search_result = None
    
    if search_plate and active_tab == 'search':
        # LOG THE SEARCH
        AuditLog.objects.create(
            user=request.user,
            action='search_vehicle_profiles',
            details=f'Searched vehicle profiles for: {search_plate}',
            ip_address=get_client_ip(request)
        )
        
        # Search for vehicle
        vehicles = Vehicle.objects.filter(plate_number__iexact=search_plate)
        
        if vehicles.exists():
            first_vehicle = vehicles.first()
            total_visits = vehicles.count()
            sites_visited = vehicles.values('site_name').distinct().count()
            
            # Get last seen
            latest_visit = vehicles.order_by('-entry_time').first()
            last_seen_time = latest_visit.entry_time
            time_diff = timezone.now() - last_seen_time
            
            if time_diff.days > 0:
                last_seen = f"{time_diff.days}d ago"
            elif time_diff.seconds >= 3600:
                last_seen = f"{time_diff.seconds // 3600}h ago"
            else:
                last_seen = f"{time_diff.seconds // 60}m ago"
            
            search_result = {
                'plate_number': first_vehicle.plate_number,
                'vehicle_type': first_vehicle.vehicle_type or 'Unknown',
                'vehicle_brand': first_vehicle.vehicle_brand or 'Unknown',
                'total_visits': total_visits,
                'sites_visited': sites_visited,
                'last_seen': last_seen,
            }
    
    # BROWSE TAB
    selected_site = request.GET.get('site', '')
    selected_vehicle_type = request.GET.get('vehicle_type', '')
    selected_status = request.GET.get('status', '')
    page = int(request.GET.get('page', 1))
    
    # Get all unique vehicles
    all_vehicles = Vehicle.objects.values('plate_number').annotate(
        latest_entry=Max('entry_time')
    ).order_by('-latest_entry')
    
    # Apply filters
    if selected_site:
        plates_at_site = Vehicle.objects.filter(site_name=selected_site).values_list('plate_number', flat=True).distinct()
        all_vehicles = all_vehicles.filter(plate_number__in=plates_at_site)
    
    if selected_vehicle_type:
        plates_of_type = Vehicle.objects.filter(vehicle_type=selected_vehicle_type).values_list('plate_number', flat=True).distinct()
        all_vehicles = all_vehicles.filter(plate_number__in=plates_of_type)
    
    # Status filter
    if selected_status == 'active':
        cutoff = timezone.now() - timedelta(days=7)
        all_vehicles = all_vehicles.filter(latest_entry__gte=cutoff)
    elif selected_status == 'inactive':
        cutoff = timezone.now() - timedelta(days=30)
        all_vehicles = all_vehicles.filter(latest_entry__lt=cutoff)
    elif selected_status == 'flagged':
        flagged_plates = VehicleFlag.objects.filter(is_active=True).values_list('plate_number', flat=True)
        all_vehicles = all_vehicles.filter(plate_number__in=flagged_plates)
    
    total_vehicles = all_vehicles.count()
    
    # Pagination (50 per page)
    per_page = 50
    total_pages = (total_vehicles + per_page - 1) // per_page
    
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    vehicles_page = list(all_vehicles[start_idx:end_idx])
    
    # Build vehicle list with details
    vehicles = []
    for v in vehicles_page:
        plate = v['plate_number']
        
        vehicle_records = Vehicle.objects.filter(plate_number=plate)
        first_record = vehicle_records.first()
        visit_count = vehicle_records.count()
        
        last_seen_time = v['latest_entry']
        time_diff = timezone.now() - last_seen_time
        
        if time_diff.days > 0:
            last_seen = f"{time_diff.days}d ago"
        elif time_diff.seconds >= 3600:
            last_seen = f"{time_diff.seconds // 3600}h ago"
        else:
            last_seen = f"{time_diff.seconds // 60}m ago"
        
        if VehicleFlag.objects.filter(plate_number=plate, is_active=True).exists():
            status = 'flagged'
        elif time_diff.days < 7:
            status = 'active'
        else:
            status = 'inactive'
        
        vehicles.append({
            'plate_number': plate,
            'plate_masked': mask_plate_number(plate),
            'vehicle_type': first_record.vehicle_type or 'Unknown',
            'vehicle_brand': first_record.vehicle_brand or 'Unknown',
            'visit_count': visit_count,
            'last_seen': last_seen,
            'status': status,
        })
    
    all_sites = Vehicle.objects.values_list('site_name', flat=True).distinct().order_by('site_name')
    vehicle_types = Vehicle.objects.exclude(
        Q(vehicle_type__isnull=True) | Q(vehicle_type='')
    ).values_list('vehicle_type', flat=True).distinct().order_by('vehicle_type')
    
    context = {
        'active_tab': active_tab,
        'search_plate': search_plate,
        'search_result': search_result,
        'vehicles': vehicles,
        'total_vehicles': total_vehicles,
        'current_page': page,
        'total_pages': total_pages,
        'all_sites': all_sites,
        'vehicle_types': vehicle_types,
        'selected_site': selected_site,
        'selected_vehicle_type': selected_vehicle_type,
        'selected_status': selected_status,
        'active_alerts_count': VehicleFlag.objects.filter(is_active=True).count(),
    }
    
    return render(request, 'vehicles/vehicle_profiles.html', context)


@login_required
def export_vehicles(request):
    """Export all vehicles to CSV"""
    import csv
    from django.http import HttpResponse
    from django.db.models import Max, Count
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="all_vehicles.csv"'
    
    writer = csv.writer(response)
    writer.writerow(['Plate Number', 'Vehicle Type', 'Brand', 'Color', 'Total Visits', 'Sites Visited', 'First Seen', 'Last Seen'])
    
    # Get all unique vehicles
    all_vehicles = Vehicle.objects.values('plate_number').annotate(
        latest_entry=Max('entry_time'),
        earliest_entry=Min('entry_time')
    )
    
    for v in all_vehicles:
        plate = v['plate_number']
        records = Vehicle.objects.filter(plate_number=plate)
        first_record = records.first()
        
        total_visits = records.count()
        sites_visited = records.values('site_name').distinct().count()
        
        writer.writerow([
            plate,
            first_record.vehicle_type or 'Unknown',
            first_record.vehicle_brand or 'Unknown',
            first_record.plate_color or 'Unknown',
            total_visits,
            sites_visited,
            v['earliest_entry'].strftime('%Y-%m-%d %H:%M') if v['earliest_entry'] else 'N/A',
            v['latest_entry'].strftime('%Y-%m-%d %H:%M') if v['latest_entry'] else 'N/A',
        ])
    
    return response

@login_required
def search_vehicles_api(request):
    """API endpoint for global search with audit logging"""
    from django.http import JsonResponse
    from django.db.models import Max, Count
    
    query = request.GET.get('q', '').strip().upper()
    
    if not query or len(query) < 2:
        return JsonResponse({'results': []})
    
    # LOG THE SEARCH
    AuditLog.objects.create(
        user=request.user,
        action='search_vehicle',
        details=f'Searched for: {query}',
        ip_address=get_client_ip(request)
    )
    
    # Search for vehicles matching the query
    matching_plates = Vehicle.objects.filter(
        plate_number__icontains=query
    ).values('plate_number').annotate(
        latest_entry=Max('entry_time')
    ).order_by('-latest_entry')[:10]  # Top 10 results
    
    results = []
    for v in matching_plates:
        plate = v['plate_number']
        records = Vehicle.objects.filter(plate_number=plate)
        first_record = records.first()
        visit_count = records.count()
        
        # Calculate last seen
        last_seen_time = v['latest_entry']
        time_diff = timezone.now() - last_seen_time
        
        if time_diff.days > 0:
            last_seen = f"{time_diff.days}d ago"
        elif time_diff.seconds >= 3600:
            last_seen = f"{time_diff.seconds // 3600}h ago"
        else:
            last_seen = f"{time_diff.seconds // 60}m ago"
        
        results.append({
            'plate_number': plate,
            'plate_masked': mask_plate_number(plate),
            'vehicle_type': first_record.vehicle_type or 'Unknown',
            'vehicle_brand': first_record.vehicle_brand or 'Unknown',
            'visit_count': visit_count,
            'last_seen': last_seen,
        })
    
    return JsonResponse({'results': results, 'total': len(results)})

@login_required
def alert_details_api(request, alert_id):
    """API endpoint to get full alert details"""
    from django.http import JsonResponse
    
    try:
        alert = VehicleFlag.objects.get(id=alert_id)
        
        data = {
            'id': alert.id,
            'plate_number': alert.plate_number,
            'reason': alert.reason,
            'description': alert.description or '',
            'priority': alert.priority,
            'rule_type_display': alert.get_rule_type_display(),
            'flagged_by': alert.flagged_by.username if alert.flagged_by else 'System',
            'flagged_at': alert.flagged_at.strftime('%b %d, %Y %H:%M'),
            'is_active': alert.is_active,
            'resolved_at': alert.resolved_at.strftime('%b %d, %Y %H:%M') if alert.resolved_at else None,
            'resolved_by': alert.resolved_by.username if alert.resolved_by else None,
            'resolution_notes': alert.resolution_notes or '',
            'email_sent': alert.email_sent,
            'sms_sent': alert.sms_sent,
        }
        
        return JsonResponse(data)
    except VehicleFlag.DoesNotExist:
        return JsonResponse({'error': 'Alert not found'}, status=404)
    
@login_required
def create_custom_rule(request):
    """Create a new custom alert rule"""
    if request.method == 'POST':
        name = request.POST.get('name')
        description = request.POST.get('description', '')
        condition_type = request.POST.get('condition_type')
        priority = request.POST.get('priority', 'medium')
        
        # Condition parameters
        threshold_hours = request.POST.get('threshold_hours')
        threshold_count = request.POST.get('threshold_count')
        threshold_sites = request.POST.get('threshold_sites')
        target_site = request.POST.get('target_site')
        time_start = request.POST.get('time_start')
        time_end = request.POST.get('time_end')
        plate_pattern = request.POST.get('plate_pattern', '')
        
        # Notifications
        send_email = request.POST.get('send_email') == '1'
        send_sms = request.POST.get('send_sms') == '1'
        email_recipients = request.POST.get('email_recipients', '')
        sms_recipients = request.POST.get('sms_recipients', '')
        
        # Create the rule
        rule = CustomAlertRule.objects.create(
            name=name,
            description=description,
            condition_type=condition_type,
            priority=priority,
            threshold_hours=int(threshold_hours) if threshold_hours else None,
            threshold_count=int(threshold_count) if threshold_count else None,
            threshold_sites=int(threshold_sites) if threshold_sites else None,
            target_site=target_site if target_site else None,
            time_start=time_start if time_start else None,
            time_end=time_end if time_end else None,
            plate_pattern=plate_pattern,
            send_email=send_email,
            send_sms=send_sms,
            email_recipients=email_recipients,
            sms_recipients=sms_recipients,
            created_by=request.user,
        )
        
        messages.success(request, f'Custom rule "{name}" created successfully!')
        return redirect('alerts_center' + '?tab=rules')
    
    return redirect('alerts_center')


@login_required
def toggle_rule_api(request, rule_id):
    """Toggle custom rule active status"""
    from django.http import JsonResponse
    import json
    
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            is_active = data.get('is_active', False)
            
            rule = CustomAlertRule.objects.get(id=rule_id)
            rule.is_active = is_active
            rule.save()
            
            return JsonResponse({'success': True})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=400)
    
    return JsonResponse({'success': False}, status=400)


@login_required
def delete_rule_api(request, rule_id):
    """Delete custom rule"""
    from django.http import JsonResponse
    
    if request.method == 'POST':
        try:
            rule = CustomAlertRule.objects.get(id=rule_id)
            rule.delete()
            
            return JsonResponse({'success': True})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)}, status=400)
    
    return JsonResponse({'success': False}, status=400)


def check_custom_rules(vehicle):
    """
    Check if a vehicle entry triggers any custom rules
    Called automatically when a vehicle enters a site
    """
    from datetime import timedelta
    import re
    
    active_rules = CustomAlertRule.objects.filter(is_active=True)
    
    for rule in active_rules:
        triggered = False
        reason = ''
        
        if rule.condition_type == 'no_exit':
            # Check if vehicle has no exit record
            if not vehicle.exit_time:
                triggered = True
                reason = f"No exit record: {rule.name}"
        
        elif rule.condition_type == 'overstay':
            # Check if vehicle overstayed
            if vehicle.exit_time and rule.threshold_hours:
                duration = (vehicle.exit_time - vehicle.entry_time).total_seconds() / 3600
                if duration > rule.threshold_hours:
                    triggered = True
                    reason = f"Overstay detected ({duration:.1f}h): {rule.name}"
        
        elif rule.condition_type == 'visit_count':
            # Check visit frequency
            if rule.threshold_count:
                today_start = timezone.now().replace(hour=0, minute=0, second=0)
                today_visits = Vehicle.objects.filter(
                    plate_number=vehicle.plate_number,
                    entry_time__gte=today_start
                ).count()
                
                if today_visits >= rule.threshold_count:
                    triggered = True
                    reason = f"High visit frequency ({today_visits} visits today): {rule.name}"
        
        elif rule.condition_type == 'rapid_movement':
            # Check rapid multi-site movement
            if rule.threshold_sites:
                recent_time = timezone.now() - timedelta(hours=2)
                recent_sites = Vehicle.objects.filter(
                    plate_number=vehicle.plate_number,
                    entry_time__gte=recent_time
                ).values('site_name').distinct().count()
                
                if recent_sites >= rule.threshold_sites:
                    triggered = True
                    reason = f"Rapid movement ({recent_sites} sites in 2h): {rule.name}"
        
        elif rule.condition_type == 'specific_site':
            # Check if vehicle entered specific site
            if rule.target_site and vehicle.site_name == rule.target_site:
                triggered = True
                reason = f"Entered monitored site ({rule.target_site}): {rule.name}"
        
        elif rule.condition_type == 'time_based':
            # Check if vehicle entered during specific time
            if rule.time_start and rule.time_end:
                entry_time = vehicle.entry_time.time()
                if rule.time_start <= entry_time <= rule.time_end:
                    triggered = True
                    reason = f"Entry during restricted hours: {rule.name}"
        
        elif rule.condition_type == 'plate_pattern':
            # WANTED VEHICLE DETECTION
            if rule.plate_pattern:
                wanted_plates = [p.strip().upper() for p in rule.plate_pattern.split('\n') if p.strip()]
                if vehicle.plate_number.upper() in wanted_plates:
                    triggered = True
                    reason = f"🚨 WANTED VEHICLE DETECTED: {rule.name}"
        
        # If rule triggered, create alert
        if triggered:
            # Check if alert already exists
            existing = VehicleFlag.objects.filter(
                plate_number=vehicle.plate_number,
                is_active=True,
                reason=reason
            ).exists()
            
            if not existing:
                alert = VehicleFlag.objects.create(
                    plate_number=vehicle.plate_number,
                    reason=reason,
                    description=rule.description or f"Auto-triggered by rule: {rule.name}",
                    priority=rule.priority,
                    rule_type='custom',
                    flagged_by=rule.created_by,
                )
                
                # Update rule stats
                rule.last_triggered = timezone.now()
                rule.trigger_count += 1
                rule.save()
                
                # Send notifications
                if rule.send_email and rule.email_recipients:
                    try:
                        send_rule_alert_email(alert, rule)
                        alert.email_sent = True
                        alert.save()
                    except Exception as e:
                        print(f"Email error: {e}")
                
                if rule.send_sms and rule.sms_recipients:
                    try:
                        send_rule_alert_sms(alert, rule)
                        alert.sms_sent = True
                        alert.save()
                    except Exception as e:
                        print(f"SMS error: {e}")


def send_rule_alert_email(alert, rule):
    """Send HTML email for custom rule trigger"""
    from django.core.mail import EmailMultipleAlternatives
    from django.conf import settings
    
    subject = f'[{alert.priority.upper()}] Alert: {rule.name}'
    
    # Plain text version
    text_content = f"""
    VEHICLE ALERT TRIGGERED
    
    Rule: {rule.name}
    Plate Number: {alert.plate_number}
    Priority: {alert.priority.upper()}
    
    Reason: {alert.reason}
    Description: {alert.description}
    
    Triggered at: {alert.flagged_at.strftime('%Y-%m-%d %H:%M:%S')}
    
    Please review this alert in the system immediately.
    """
    
    # HTML version
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; background: #f5f5f5; padding: 20px; }}
            .container {{ max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
            .header {{ background: {'#ef4444' if alert.priority == 'critical' else '#f59e0b' if alert.priority == 'high' else '#3b82f6'}; color: white; padding: 30px; text-align: center; }}
            .content {{ padding: 30px; }}
            .alert-box {{ background: #fef3c7; border-left: 4px solid #f59e0b; padding: 15px; margin: 20px 0; }}
            .info-row {{ padding: 12px 0; border-bottom: 1px solid #e5e7eb; }}
            .label {{ font-weight: bold; color: #6b7280; }}
            .value {{ color: #111827; }}
            .footer {{ background: #f9fafb; padding: 20px; text-align: center; color: #6b7280; font-size: 0.875rem; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1 style="margin: 0;">🚨 VEHICLE ALERT</h1>
                <p style="margin: 10px 0 0 0; font-size: 1.1rem;">{alert.priority.upper()} PRIORITY</p>
            </div>
            <div class="content">
                <div class="alert-box">
                    <strong>Rule Triggered:</strong> {rule.name}
                </div>
                
                <div class="info-row">
                    <span class="label">Plate Number:</span>
                    <span class="value" style="font-family: monospace; font-size: 1.2rem; font-weight: bold;">{alert.plate_number}</span>
                </div>
                
                <div class="info-row">
                    <span class="label">Reason:</span>
                    <span class="value">{alert.reason}</span>
                </div>
                
                <div class="info-row">
                    <span class="label">Description:</span>
                    <span class="value">{alert.description}</span>
                </div>
                
                <div class="info-row">
                    <span class="label">Triggered At:</span>
                    <span class="value">{alert.flagged_at.strftime('%B %d, %Y at %H:%M:%S')}</span>
                </div>
                
                <div style="margin-top: 30px; text-align: center;">
                    <a href="#" style="background: #10b981; color: white; padding: 12px 32px; text-decoration: none; border-radius: 6px; display: inline-block; font-weight: bold;">
                        View in System
                    </a>
                </div>
            </div>
            <div class="footer">
                Vehicle Intelligence System - Automated Alert<br>
                This is an automated message. Please do not reply to this email.
            </div>
        </div>
    </body>
    </html>
    """
    
    # Send to all recipients
    recipients = [email.strip() for email in rule.email_recipients.split(',') if email.strip()]
    
    msg = EmailMultipleAlternatives(subject, text_content, settings.DEFAULT_FROM_EMAIL, recipients)
    msg.attach_alternative(html_content, "text/html")
    msg.send()


def send_rule_alert_sms(alert, rule):
    """Send SMS for custom rule trigger via Africa's Talking"""
    from django.conf import settings
    
    recipients = [phone.strip() for phone in rule.sms_recipients.split(',') if phone.strip()]
    
    message = f"ALERT [{alert.priority.upper()}]: {alert.plate_number} - {alert.reason}. Check system immediately."
    
    # Africa's Talking Integration
    try:
        import africastalking
        
        # Initialize SDK
        africastalking.initialize(
            username=getattr(settings, 'AFRICASTALKING_USERNAME', 'sandbox'),
            api_key=getattr(settings, 'AFRICASTALKING_API_KEY', '')
        )
        
        # Get SMS service
        sms = africastalking.SMS
        
        # Send message
        response = sms.send(message, recipients)
        print(f"SMS sent successfully: {response}")
        
        return True
    except Exception as e:
        print(f"SMS sending error: {e}")
        return False   
    
@login_required
def site_intelligence(request):
    """Detailed analytics for a specific site"""
    from datetime import timedelta
    from django.db.models.functions import ExtractHour, ExtractWeekDay, TruncDate
    import json
    
    # Get selected site
    site_name = request.GET.get('site', '')
    
    # Get all sites for dropdown
    all_sites = Vehicle.objects.values_list('site_name', flat=True).distinct().order_by('site_name')
    
    if not site_name:
        context = {
            'site_name': None,
            'all_sites': all_sites,
            'active_alerts_count': VehicleFlag.objects.filter(is_active=True).count(),
        }
        return render(request, 'site_intelligence.html', context)
    
    # Filter vehicles for this site
    site_vehicles = Vehicle.objects.filter(site_name=site_name)
    
    # STATS
    total_entries = site_vehicles.count()
    current_occupancy = site_vehicles.filter(exit_time__isnull=True).count()
    unique_vehicles = site_vehicles.values('plate_number').distinct().count()
    
    # Average duration
    vehicles_with_duration = site_vehicles.filter(exit_time__isnull=False).annotate(
        duration=ExpressionWrapper(
            F('exit_time') - F('entry_time'),
            output_field=DurationField()
        )
    )
    
    avg_duration = 'N/A'
    if vehicles_with_duration.exists():
        avg_dur = vehicles_with_duration.aggregate(avg=Avg('duration'))['avg']
        if avg_dur:
            hours = int(avg_dur.total_seconds() // 3600)
            minutes = int((avg_dur.total_seconds() % 3600) // 60)
            avg_duration = f"{hours}h {minutes}m"
    
    # Today's entries
    today_start = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
    today_entries = site_vehicles.filter(entry_time__gte=today_start).count()
    
    stats = {
        'total_entries': total_entries,
        'current_occupancy': current_occupancy,
        'unique_vehicles': unique_vehicles,
        'avg_duration': avg_duration,
        'today_entries': today_entries,
    }
    
    # HEATMAP DATA (Hour x Day of Week for last 7 days)
    seven_days_ago = timezone.now() - timedelta(days=7)
    heatmap_vehicles = site_vehicles.filter(entry_time__gte=seven_days_ago)
    
    # Initialize 24x7 grid (hours x days)
    heatmap_grid = [[0 for _ in range(7)] for _ in range(24)]
    
    heatmap_data_raw = heatmap_vehicles.annotate(
        hour=ExtractHour('entry_time'),
        weekday=ExtractWeekDay('entry_time')  # 1=Sunday, 7=Saturday
    ).values('hour', 'weekday').annotate(count=Count('id'))
    
    for item in heatmap_data_raw:
        hour = item['hour']
        weekday = item['weekday'] - 1  # Convert to 0-6 (0=Sunday)
        if 0 <= weekday < 7:
            heatmap_grid[hour][weekday] = item['count']
    
    heatmap_data = {
        'z': heatmap_grid,
        'x': ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'],
        'y': [f"{h:02d}:00" for h in range(24)]
    }
    
    # TREND DATA (Last 30 days)
    thirty_days_ago = timezone.now() - timedelta(days=30)
    trend_vehicles = site_vehicles.filter(entry_time__gte=thirty_days_ago)
    
    trend_data_raw = trend_vehicles.annotate(
        date=TruncDate('entry_time')
    ).values('date').annotate(count=Count('id')).order_by('date')
    
    trend_data = []
    for item in trend_data_raw:
        trend_data.append({
            'date': item['date'].strftime('%b %d'),
            'count': item['count']
        })
    
    # VEHICLE TYPE DATA
    vehicle_type_raw = site_vehicles.values('vehicle_type').annotate(
        count=Count('id')
    ).order_by('-count')[:5]
    
    vehicle_type_data = []
    for item in vehicle_type_raw:
        vehicle_type_data.append({
            'type': item['vehicle_type'] or 'Unknown',
            'count': item['count']
        })
    
    # PEAK HOURS DATA
    peak_hours_raw = site_vehicles.annotate(
        hour=ExtractHour('entry_time')
    ).values('hour').annotate(count=Count('id')).order_by('-count')[:10]
    
    peak_hours_data = []
    for item in peak_hours_raw:
        peak_hours_data.append({
            'hour': item['hour'],
            'count': item['count']
        })
    
    # Sort by hour for better visualization
    peak_hours_data.sort(key=lambda x: x['hour'])
    
    # TOP VEHICLES AT THIS SITE
    top_vehicles_raw = site_vehicles.values('plate_number').annotate(
        visit_count=Count('id'),
        latest_visit=Max('entry_time')
    ).order_by('-visit_count')[:20]
    
    top_vehicles = []
    for v in top_vehicles_raw:
        plate = v['plate_number']
        
        # Get vehicle details
        vehicle_records = site_vehicles.filter(plate_number=plate)
        first_record = vehicle_records.first()
        
        # Calculate average duration
        records_with_duration = vehicle_records.filter(exit_time__isnull=False).annotate(
            duration=ExpressionWrapper(
                F('exit_time') - F('entry_time'),
                output_field=DurationField()
            )
        )
        
        avg_dur = 'N/A'
        if records_with_duration.exists():
            avg_duration_obj = records_with_duration.aggregate(avg=Avg('duration'))['avg']
            if avg_duration_obj:
                hrs = int(avg_duration_obj.total_seconds() // 3600)
                mins = int((avg_duration_obj.total_seconds() % 3600) // 60)
                avg_dur = f"{hrs}h {mins}m"
        
        # Last visit
        last_visit_time = v['latest_visit']
        time_diff = timezone.now() - last_visit_time
        
        if time_diff.days > 0:
            last_visit = f"{time_diff.days}d ago"
        elif time_diff.seconds >= 3600:
            last_visit = f"{time_diff.seconds // 3600}h ago"
        else:
            last_visit = f"{time_diff.seconds // 60}m ago"
        
        top_vehicles.append({
            'plate_number': plate,
            'plate_masked': mask_plate_number(plate),
            'vehicle_type': first_record.vehicle_type or 'Unknown',
            'visit_count': v['visit_count'],
            'last_visit': last_visit,
            'avg_duration': avg_dur,
        })
    
    context = {
        'site_name': site_name,
        'all_sites': all_sites,
        'stats': stats,
        'heatmap_data': json.dumps(heatmap_data),
        'trend_data': json.dumps(trend_data),
        'vehicle_type_data': json.dumps(vehicle_type_data),
        'peak_hours_data': json.dumps(peak_hours_data),
        'top_vehicles': top_vehicles,
        'active_alerts_count': VehicleFlag.objects.filter(is_active=True).count(),
    }
    
    return render(request, 'site_intelligence.html', context)


@login_required
def export_site_report(request):
    """Export comprehensive site report to CSV"""
    import csv
    from django.http import HttpResponse
    
    site_name = request.GET.get('site', '')
    
    if not site_name:
        return redirect('site_intelligence')
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="site_report_{site_name}_{timezone.now().strftime("%Y%m%d")}.csv"'
    
    writer = csv.writer(response)
    
    # Header
    writer.writerow(['SITE INTELLIGENCE REPORT'])
    writer.writerow(['Site:', site_name])
    writer.writerow(['Generated:', timezone.now().strftime('%Y-%m-%d %H:%M:%S')])
    writer.writerow([])
    
    # Summary stats
    site_vehicles = Vehicle.objects.filter(site_name=site_name)
    total_entries = site_vehicles.count()
    current_occupancy = site_vehicles.filter(exit_time__isnull=True).count()
    unique_vehicles = site_vehicles.values('plate_number').distinct().count()
    
    writer.writerow(['SUMMARY STATISTICS'])
    writer.writerow(['Total Entries', total_entries])
    writer.writerow(['Current Occupancy', current_occupancy])
    writer.writerow(['Unique Vehicles', unique_vehicles])
    writer.writerow([])
    
    # Top vehicles
    writer.writerow(['TOP VEHICLES'])
    writer.writerow(['Rank', 'Plate Number', 'Vehicle Type', 'Visit Count', 'Last Visit'])
    
    top_vehicles = site_vehicles.values('plate_number').annotate(
        visit_count=Count('id'),
        latest_visit=Max('entry_time')
    ).order_by('-visit_count')[:50]
    
    for idx, v in enumerate(top_vehicles, 1):
        first_record = site_vehicles.filter(plate_number=v['plate_number']).first()
        writer.writerow([
            idx,
            v['plate_number'],
            first_record.vehicle_type or 'Unknown',
            v['visit_count'],
            v['latest_visit'].strftime('%Y-%m-%d %H:%M') if v['latest_visit'] else 'N/A'
        ])
    
    return response    