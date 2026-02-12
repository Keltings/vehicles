from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db.models import Count, Max, Q, F, ExpressionWrapper, DurationField
from django.utils import timezone
from datetime import timedelta
from .models import CustomUser, Vehicle, VehicleFlag, AuditLog

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
    from datetime import timedelta
    
    # Get basic stats
    total_vehicles = Vehicle.objects.count()
    active_sites = Vehicle.objects.values('site_name').distinct().count()
    flagged_vehicles = VehicleFlag.objects.filter(is_active=True).count()
    
    # Today's data
    today_start = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
    todays_entries = Vehicle.objects.filter(entry_time__gte=today_start).count()
    
    # Yesterday's data for comparison
    yesterday_start = today_start - timedelta(days=1)
    yesterday_entries = Vehicle.objects.filter(
        entry_time__gte=yesterday_start,
        entry_time__lt=today_start
    ).count()
    
    # Calculate trend
    if yesterday_entries > 0:
        trend_percent = round(((todays_entries - yesterday_entries) / yesterday_entries) * 100, 1)
    else:
        trend_percent = 0
    
    # Vehicles without exit (potential issues)
    no_exit_vehicles = Vehicle.objects.filter(exit_time__isnull=True).count()
    
    # Recent vehicles
    recent_vehicles = Vehicle.objects.order_by('-entry_time')[:10]
    
    context = {
        'total_vehicles': total_vehicles,
        'active_sites': active_sites,
        'flagged_vehicles': flagged_vehicles,
        'todays_entries': todays_entries,
        'yesterday_entries': yesterday_entries,
        'trend_percent': trend_percent,
        'no_exit_vehicles': no_exit_vehicles,
        'recent_vehicles': recent_vehicles,
    }
    
    return render(request, 'dashboard.html', context)


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
def vehicle_list(request):
    """List all vehicles"""
    vehicles = Vehicle.objects.values('plate_number').annotate(
        visit_count=Count('id'),
        last_seen=Max('entry_time')
    ).order_by('-last_seen')[:100]
    
    context = {
        'vehicles': vehicles,
    }
    
    return render(request, 'vehicles/vehicle_list.html', context)

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
    """Alerts management"""
    active_alerts = VehicleFlag.objects.filter(is_active=True).order_by('-created_at')
    
    context = {
        'active_alerts': active_alerts,
    }
    
    return render(request, 'alerts/alerts_center.html', context)

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
    flagged = VehicleFlag.objects.filter(is_active=True).order_by('-created_at')
    
    # Get recent unique plates for autocomplete (last 100)
    recent_plates = Vehicle.objects.values_list('plate_number', flat=True).distinct().order_by('-entry_time')[:100]

    context = {
        'flagged_vehicles': flagged,
        'recent_plates': recent_plates,
}
    
    return render(request, 'alerts/watchlist.html', context)

@login_required
def vehicle_detail_api(request, plate_number):
    """API endpoint to get vehicle details"""
    import json
    from django.http import JsonResponse
    from django.db.models import Count, Min, Max, Avg, F, ExpressionWrapper, DurationField
    
    # Get all records for this vehicle
    vehicles = Vehicle.objects.filter(plate_number__iexact=plate_number).order_by('-entry_time')
    
    if not vehicles.exists():
        return JsonResponse({'error': 'Vehicle not found'}, status=404)
    
    # Get basic info from most recent record
    latest = vehicles.first()
    
    # Calculate statistics
    total_visits = vehicles.count()
    sites_visited = vehicles.values('site_name').distinct().count()
    
    # Get visit history (last 10)
    visit_history = []
    for v in vehicles[:10]:
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
        })
    
    # Calculate average duration
    vehicles_with_duration = vehicles.filter(exit_time__isnull=False).annotate(
        duration=ExpressionWrapper(F('exit_time') - F('entry_time'), output_field=DurationField())
    )
    
    avg_duration = None
    if vehicles_with_duration.exists():
        avg_duration_obj = vehicles_with_duration.aggregate(avg=Avg('duration'))['avg']
        if avg_duration_obj:
            avg_hours = int(avg_duration_obj.total_seconds() // 3600)
            avg_minutes = int((avg_duration_obj.total_seconds() % 3600) // 60)
            avg_duration = f"{avg_hours}h {avg_minutes}m"
    
    # Get most frequent site
    site_counts = vehicles.values('site_name').annotate(count=Count('id')).order_by('-count')
    most_frequent_site = site_counts.first()['site_name'] if site_counts.exists() else 'N/A'
    
    # Check if flagged
    is_flagged = VehicleFlag.objects.filter(plate_number__iexact=plate_number, is_active=True).exists()
    flag_info = None
    if is_flagged:
        flag = VehicleFlag.objects.filter(plate_number__iexact=plate_number, is_active=True).first()
        flag_info = {
            'reason': flag.get_reason_display(),
            'priority': flag.get_priority_display(),
            'description': flag.description
        }
    
    # Risk assessment
    risk_score = 'LOW'
    risk_factors = []
    
    # Check for no-exit records
    no_exit_count = vehicles.filter(exit_time__isnull=True).count()
    if no_exit_count > 0:
        risk_factors.append(f'{no_exit_count} visit(s) without exit recorded')
        if no_exit_count > 2:
            risk_score = 'MEDIUM'
    
    # Check for high frequency
    if total_visits > 20:
        risk_factors.append(f'High frequency visitor ({total_visits} visits)')
        if total_visits > 50:
            risk_score = 'MEDIUM'
    
    # Check if flagged
    if is_flagged:
        risk_factors.append('Vehicle is flagged in system')
        risk_score = 'HIGH'
    
    if not risk_factors:
        risk_factors.append('No unusual patterns detected')
    
    data = {
        'plate_number': latest.plate_number,
        'vehicle_type': latest.vehicle_type or 'Unknown',
        'vehicle_brand': latest.vehicle_brand or 'Unknown',
        'plate_color': latest.plate_color or 'Unknown',
        'first_seen': vehicles.aggregate(Min('entry_time'))['entry_time__min'].strftime('%b %d, %Y'),
        'last_seen': latest.entry_time.strftime('%b %d, %Y %H:%M'),
        'total_visits': total_visits,
        'sites_visited': sites_visited,
        'most_frequent_site': most_frequent_site,
        'avg_duration': avg_duration or 'N/A',
        'visit_history': visit_history,
        'is_flagged': is_flagged,
        'flag_info': flag_info,
        'risk_score': risk_score,
        'risk_factors': risk_factors,
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