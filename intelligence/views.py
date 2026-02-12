from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db.models import Count, Max, Q, F, ExpressionWrapper, DurationField,Avg
from django.utils import timezone
from datetime import timedelta, datetime
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
    recent_flags = VehicleFlag.objects.filter(is_active=True).order_by('-created_at')[:3]

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
            'time': flag.created_at.strftime('%b %d, %Y %H:%M')
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