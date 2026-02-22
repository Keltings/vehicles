from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, JsonResponse
from django.utils import timezone
from django.db.models import Count, Sum, Avg, F, ExpressionWrapper, DurationField, Q, Min, Max
from intelligence.models import Vehicle, CustomUser, AuditLog
from datetime import timedelta
import random
import json

# Store OTPs temporarily (in production, use Redis or database)
otp_storage = {}

def get_client_ip(request):
    """Get client IP address"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def owner_login(request):
    """Login page for car owners - enter plate number to get OTP"""
    if request.user.is_authenticated:
        return redirect('owner_portal:dashboard')
    
    if request.method == 'POST':
        plate_number = request.POST.get('plate_number', '').strip().upper()
        
        # Check if vehicle exists
        if not Vehicle.objects.filter(plate_number=plate_number).exists():
            messages.error(request, 'Vehicle not found in our system.')
            return render(request, 'owner/login.html')
        
        # Generate 6-digit OTP
        otp = str(random.randint(100000, 999999))
        
        # Store OTP (expires in 10 minutes)
        otp_storage[plate_number] = {
            'otp': otp,
            'expires': timezone.now() + timedelta(minutes=10)
        }
        
        # In production, send OTP via SMS/Email
        # For now, we'll display it (DEMO MODE)
        print(f"OTP for {plate_number}: {otp}")
        
        # Log the login attempt
        AuditLog.objects.create(
            user=None,
            action='owner_login_attempt',
            details=f'OTP requested for {plate_number}',
            ip_address=get_client_ip(request)
        )
        
        messages.success(request, f'OTP sent! (Demo mode: {otp})')
        return render(request, 'owner/verify_otp.html', {'plate_number': plate_number})
    
    return render(request, 'owner/login.html')


def verify_otp(request):
    """Verify OTP and log user in"""
    if request.method == 'POST':
        plate_number = request.POST.get('plate_number', '').strip().upper()
        entered_otp = request.POST.get('otp', '').strip()
        
        # Check if OTP exists
        if plate_number not in otp_storage:
            messages.error(request, 'OTP expired or invalid. Please try again.')
            return redirect('owner_portal:login')
        
        stored_data = otp_storage[plate_number]
        
        # Check if OTP expired
        if timezone.now() > stored_data['expires']:
            del otp_storage[plate_number]
            messages.error(request, 'OTP expired. Please request a new one.')
            return redirect('owner_portal:login')
        
        # Check if OTP matches
        if entered_otp != stored_data['otp']:
            messages.error(request, 'Invalid OTP. Please try again.')
            return render(request, 'owner/verify_otp.html', {'plate_number': plate_number})
        
        # OTP verified! Create session
        request.session['owner_plate'] = plate_number
        request.session['owner_logged_in'] = True
        
        # Clean up OTP
        del otp_storage[plate_number]
        
        # Log successful login
        AuditLog.objects.create(
            user=None,
            action='owner_login_success',
            details=f'Car owner logged in: {plate_number}',
            ip_address=get_client_ip(request)
        )
        
        messages.success(request, f'Welcome! Viewing history for {plate_number}')
        return redirect('owner_portal:dashboard')
    
    return redirect('owner_portal:login')


def owner_logout(request):
    """Logout car owner"""
    plate = request.session.get('owner_plate', 'Unknown')
    
    # Log logout
    AuditLog.objects.create(
        user=None,
        action='owner_logout',
        details=f'Car owner logged out: {plate}',
        ip_address=get_client_ip(request)
    )
    
    request.session.flush()
    messages.success(request, 'You have been logged out.')
    return redirect('owner_portal:login')


def owner_required(view_func):
    """Decorator to check if car owner is logged in"""
    def wrapper(request, *args, **kwargs):
        if not request.session.get('owner_logged_in'):
            messages.error(request, 'Please log in to continue.')
            return redirect('owner_portal:login')
        return view_func(request, *args, **kwargs)
    return wrapper


@owner_required
def owner_dashboard(request):
    """Car owner dashboard - summary and recent history"""
    plate_number = request.session.get('owner_plate')
    
    # Get all records for this vehicle
    all_records = Vehicle.objects.filter(plate_number=plate_number).order_by('-entry_time')
    
    if not all_records.exists():
        context = {
            'plate_number': plate_number,
            'no_data': True,
        }
        return render(request, 'owner/dashboard.html', context)
    
    # Summary stats
    total_visits = all_records.count()
    sites_visited = all_records.values('site_name').distinct().count()
    
    # Total paid
    total_paid = all_records.filter(amount_paid__isnull=False).aggregate(
        total=Sum('amount_paid')
    )['total'] or 0
    
    # Average duration
    records_with_duration = all_records.filter(exit_time__isnull=False).annotate(
        duration=ExpressionWrapper(
            F('exit_time') - F('entry_time'),
            output_field=DurationField()
        )
    )
    
    avg_duration = 'N/A'
    if records_with_duration.exists():
        avg_dur = records_with_duration.aggregate(avg=Avg('duration'))['avg']
        if avg_dur:
            hours = int(avg_dur.total_seconds() // 3600)
            minutes = int((avg_dur.total_seconds() % 3600) // 60)
            avg_duration = f"{hours}h {minutes}m"
    
    # Recent history (last 10)
    recent_visits = []
    for v in all_records[:10]:
        duration = None
        if v.exit_time and v.entry_time:
            duration_seconds = (v.exit_time - v.entry_time).total_seconds()
            hours = int(duration_seconds // 3600)
            minutes = int((duration_seconds % 3600) // 60)
            duration = f"{hours}h {minutes}m"
        
        recent_visits.append({
            'id': v.id,
            'site': v.site_name,
            'entry': v.entry_time,
            'exit': v.exit_time,
            'duration': duration or 'N/A',
            'amount_paid': float(v.amount_paid) if v.amount_paid else 0,
            'payment_method': v.payment_method or 'N/A',
            'status': 'Completed' if v.exit_time else 'In Progress',
        })
    
    # Most visited site
    most_visited = all_records.values('site_name').annotate(
        count=Count('id')
    ).order_by('-count').first()
    
    most_visited_site = most_visited['site_name'] if most_visited else 'N/A'
    
    # Preferred payment method
    preferred_payment = all_records.exclude(
        Q(payment_method__isnull=True) | Q(payment_method='')
    ).values('payment_method').annotate(
        count=Count('id')
    ).order_by('-count').first()
    
    preferred_payment_method = preferred_payment['payment_method'] if preferred_payment else 'N/A'
    
    # First visit
    first_visit = all_records.order_by('entry_time').first()
    
    # Vehicle info
    vehicle_info = {
        'type': first_visit.vehicle_type or 'Unknown',
        'brand': first_visit.vehicle_brand or 'Unknown',
        'color': first_visit.plate_color or 'Unknown',
    }
    
    context = {
        'plate_number': plate_number,
        'total_visits': total_visits,
        'sites_visited': sites_visited,
        'total_paid': total_paid,
        'avg_duration': avg_duration,
        'recent_visits': recent_visits,
        'most_visited_site': most_visited_site,
        'preferred_payment_method': preferred_payment_method,
        'first_visit_date': first_visit.entry_time,
        'vehicle_info': vehicle_info,
    }
    
    return render(request, 'owner/dashboard.html', context)


@owner_required
def parking_history(request):
    """Full parking history with filters"""
    plate_number = request.session.get('owner_plate')
    
    # Get filters
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')
    site = request.GET.get('site', '')
    
    # Base queryset
    visits = Vehicle.objects.filter(plate_number=plate_number).order_by('-entry_time')
    
    # Apply filters
    if date_from:
        from datetime import datetime
        date_from_obj = datetime.strptime(date_from, '%Y-%m-%d')
        visits = visits.filter(entry_time__gte=date_from_obj)
    
    if date_to:
        from datetime import datetime
        date_to_obj = datetime.strptime(date_to, '%Y-%m-%d')
        date_to_obj = date_to_obj.replace(hour=23, minute=59, second=59)
        visits = visits.filter(entry_time__lte=date_to_obj)
    
    if site:
        visits = visits.filter(site_name=site)
    
    # Build history list
    history = []
    for v in visits:
        duration = None
        if v.exit_time and v.entry_time:
            duration_seconds = (v.exit_time - v.entry_time).total_seconds()
            hours = int(duration_seconds // 3600)
            minutes = int((duration_seconds % 3600) // 60)
            duration = f"{hours}h {minutes}m"
        
        history.append({
            'id': v.id,
            'site': v.site_name,
            'entry': v.entry_time,
            'exit': v.exit_time,
            'duration': duration or 'N/A',
            'amount_paid': float(v.amount_paid) if v.amount_paid else 0,
            'payment_method': v.payment_method or 'N/A',
            'status': 'Completed' if v.exit_time else 'In Progress',
        })
    
    # Get all sites for filter
    all_sites = Vehicle.objects.filter(plate_number=plate_number).values_list('site_name', flat=True).distinct()
    
    context = {
        'plate_number': plate_number,
        'history': history,
        'total_records': len(history),
        'all_sites': all_sites,
        'date_from': date_from,
        'date_to': date_to,
        'selected_site': site,
    }
    
    return render(request, 'owner/history.html', context)


@owner_required
def payment_history(request):
    """Payment history and summary"""
    plate_number = request.session.get('owner_plate')
    
    # Get all paid records
    payments = Vehicle.objects.filter(
        plate_number=plate_number,
        amount_paid__isnull=False,
        amount_paid__gt=0
    ).order_by('-payment_time')
    
    # Build payment list
    payment_list = []
    for p in payments:
        payment_list.append({
            'id': p.id,
            'date': p.payment_time or p.entry_time,
            'site': p.site_name,
            'amount': float(p.amount_paid),
            'method': p.payment_method or 'N/A',
        })
    
    # Summary
    total_paid = sum(p['amount'] for p in payment_list)
    total_transactions = len(payment_list)
    
    # Monthly breakdown (last 6 months)
    from django.db.models.functions import TruncMonth
    monthly = payments.annotate(
        month=TruncMonth('payment_time')
    ).values('month').annotate(
        total=Sum('amount_paid')
    ).order_by('-month')[:6]
    
    monthly_breakdown = []
    for m in monthly:
        monthly_breakdown.append({
            'month': m['month'].strftime('%B %Y') if m['month'] else 'Unknown',
            'total': float(m['total']) if m['total'] else 0,
        })
    
    # Calculate average per transaction
    avg_per_transaction = (total_paid / total_transactions) if total_transactions > 0 else 0
    
    context = {
        'plate_number': plate_number,
        'payments': payment_list,
        'total_paid': total_paid,
        'total_transactions': total_transactions,
        'avg_per_transaction': avg_per_transaction,
        'monthly_breakdown': monthly_breakdown,
    }
    
    return render(request, 'owner/payments.html', context)


@owner_required
def download_receipt(request, vehicle_id):
    """Download PDF receipt for a specific parking session"""
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.units import inch
    from io import BytesIO
    
    plate_number = request.session.get('owner_plate')
    
    # Get the vehicle record (verify ownership)
    try:
        vehicle = Vehicle.objects.get(id=vehicle_id, plate_number=plate_number)
    except Vehicle.DoesNotExist:
        messages.error(request, 'Record not found.')
        return redirect('owner_portal:dashboard')
    
    # Create PDF
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    elements = []
    styles = getSampleStyleSheet()
    
    # Title
    title = Paragraph("<b>PARKING RECEIPT</b>", styles['Title'])
    elements.append(title)
    elements.append(Spacer(1, 0.3*inch))
    
    # Receipt details
    data = [
        ['Receipt Date:', timezone.now().strftime('%B %d, %Y %H:%M')],
        ['', ''],
        ['VEHICLE INFORMATION', ''],
        ['Plate Number:', plate_number],
        ['Vehicle Type:', vehicle.vehicle_type or 'N/A'],
        ['Vehicle Brand:', vehicle.vehicle_brand or 'N/A'],
        ['', ''],
        ['PARKING DETAILS', ''],
        ['Site:', vehicle.site_name],
        ['Entry Time:', vehicle.entry_time.strftime('%B %d, %Y %H:%M')],
        ['Exit Time:', vehicle.exit_time.strftime('%B %d, %Y %H:%M') if vehicle.exit_time else 'N/A'],
    ]
    
    # Calculate duration
    if vehicle.exit_time and vehicle.entry_time:
        duration_seconds = (vehicle.exit_time - vehicle.entry_time).total_seconds()
        hours = int(duration_seconds // 3600)
        minutes = int((duration_seconds % 3600) // 60)
        duration = f"{hours}h {minutes}m"
    else:
        duration = 'N/A'
    
    data.append(['Duration:', duration])
    data.append(['', ''])
    data.append(['PAYMENT INFORMATION', ''])
    data.append(['Amount Paid:', f"KSh {vehicle.amount_paid or 0:.2f}"])
    data.append(['Payment Method:', vehicle.payment_method or 'N/A'])
    data.append(['Payment Time:', vehicle.payment_time.strftime('%B %d, %Y %H:%M') if vehicle.payment_time else 'N/A'])
    
    table = Table(data, colWidths=[2.5*inch, 3.5*inch])
    table.setStyle(TableStyle([
        ('FONT', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONT', (0, 2), (1, 2), 'Helvetica-Bold'),
        ('FONT', (0, 8), (1, 8), 'Helvetica-Bold'),
        ('FONT', (0, 13), (1, 13), 'Helvetica-Bold'),
        ('TEXTCOLOR', (0, 2), (1, 2), colors.green),
        ('TEXTCOLOR', (0, 8), (1, 8), colors.green),
        ('TEXTCOLOR', (0, 13), (1, 13), colors.green),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    
    elements.append(table)
    elements.append(Spacer(1, 0.5*inch))
    
    # Footer
    footer_text = Paragraph(
        "<i>This is an automatically generated receipt. For inquiries, please contact support.</i>",
        styles['Normal']
    )
    elements.append(footer_text)
    
    doc.build(elements)
    
    # Return PDF
    buffer.seek(0)
    response = HttpResponse(buffer, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="receipt_{vehicle.id}_{plate_number}.pdf"'
    
    # Log download
    AuditLog.objects.create(
        user=None,
        action='owner_download_receipt',
        details=f'{plate_number} downloaded receipt for visit {vehicle.id}',
        ip_address=get_client_ip(request)
    )
    
    return response


@owner_required
def download_summary(request):
    """Download complete parking summary PDF"""
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.units import inch
    from io import BytesIO
    
    plate_number = request.session.get('owner_plate')
    
    # Get all records
    all_records = Vehicle.objects.filter(plate_number=plate_number).order_by('-entry_time')
    
    # Create PDF
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    elements = []
    styles = getSampleStyleSheet()
    
    # Title
    title = Paragraph(f"<b>PARKING SUMMARY REPORT</b>", styles['Title'])
    elements.append(title)
    elements.append(Spacer(1, 0.2*inch))
    
    subtitle = Paragraph(f"Vehicle: {plate_number}", styles['Heading2'])
    elements.append(subtitle)
    elements.append(Spacer(1, 0.3*inch))
    
    # Summary stats
    total_visits = all_records.count()
    total_paid = all_records.filter(amount_paid__isnull=False).aggregate(
        total=Sum('amount_paid')
    )['total'] or 0
    
    summary_data = [
        ['Total Visits:', str(total_visits)],
        ['Total Amount Paid:', f"KSh {total_paid:.2f}"],
        ['Report Generated:', timezone.now().strftime('%B %d, %Y %H:%M')],
    ]
    
    summary_table = Table(summary_data, colWidths=[2*inch, 3*inch])
    summary_table.setStyle(TableStyle([
        ('FONT', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
    ]))
    
    elements.append(summary_table)
    elements.append(Spacer(1, 0.4*inch))
    
    # Recent visits table
    recent_title = Paragraph("<b>Recent Parking History (Last 20)</b>", styles['Heading3'])
    elements.append(recent_title)
    elements.append(Spacer(1, 0.2*inch))
    
    # Table headers
    history_data = [['Date', 'Site', 'Duration', 'Amount']]
    
    for v in all_records[:20]:
        duration = 'N/A'
        if v.exit_time and v.entry_time:
            duration_seconds = (v.exit_time - v.entry_time).total_seconds()
            hours = int(duration_seconds // 3600)
            minutes = int((duration_seconds % 3600) // 60)
            duration = f"{hours}h {minutes}m"
        
        history_data.append([
            v.entry_time.strftime('%b %d, %Y'),
            v.site_name,
            duration,
            f"KSh {v.amount_paid or 0:.2f}",
        ])
    
    history_table = Table(history_data, colWidths=[1.5*inch, 2*inch, 1.5*inch, 1.5*inch])
    history_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.green),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONT', (0, 1), (-1, -1), 'Helvetica', 9),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    
    elements.append(history_table)
    
    doc.build(elements)
    
    # Return PDF
    buffer.seek(0)
    response = HttpResponse(buffer, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="parking_summary_{plate_number}.pdf"'
    
    # Log download
    AuditLog.objects.create(
        user=None,
        action='owner_download_summary',
        details=f'{plate_number} downloaded complete summary',
        ip_address=get_client_ip(request)
    )
    
    return response

@owner_required
def parking_availability(request):
    """Show real-time parking availability across all sites"""
    from django.db.models import Count, Avg, F, ExpressionWrapper, DurationField
    from django.db.models.functions import ExtractHour
    from datetime import timedelta
    
    plate_number = request.session.get('owner_plate')
    
    # Get all sites
    all_sites = Vehicle.objects.values_list('site_name', flat=True).distinct().order_by('site_name')
    
    sites_data = []
    
    for site in all_sites:
        site_vehicles = Vehicle.objects.filter(site_name=site)
        
        # Current estimated occupancy (vehicles with no exit)
        current_occupancy = site_vehicles.filter(exit_time__isnull=True).count()
        
        # Total entries today (for activity level)
        today_start = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
        today_entries = site_vehicles.filter(entry_time__gte=today_start).count()
        
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
        
        # Peak hours (top 3 busiest hours)
        peak_hours_data = site_vehicles.annotate(
            hour=ExtractHour('entry_time')
        ).values('hour').annotate(
            count=Count('id')
        ).order_by('-count')[:3]
        
        peak_hours = []
        for ph in peak_hours_data:
            peak_hours.append(f"{ph['hour']:02d}:00")
        
        peak_hours_str = ', '.join(peak_hours) if peak_hours else 'N/A'
        
        # Typical fee range
        fee_data = site_vehicles.filter(amount_paid__isnull=False, amount_paid__gt=0).aggregate(
            min_fee=Min('amount_paid'),
            max_fee=Max('amount_paid')
        )
        
        if fee_data['min_fee'] and fee_data['max_fee']:
            typical_fee = f"KSh {int(fee_data['min_fee'])}-{int(fee_data['max_fee'])}"
        else:
            typical_fee = 'N/A'
        
        # Determine status based on current occupancy
        # Since we don't have capacity, we'll use activity level
        if current_occupancy > 200:
            status = 'busy'
            status_text = '🟡 MODERATE'
            status_color = 'warning'
        elif current_occupancy > 100:
            status = 'available'
            status_text = '🟢 AVAILABLE'
            status_color = 'success'
        else:
            status = 'quiet'
            status_text = '🟢 QUIET'
            status_color = 'success'
        
        # Check if user has visited this site before
        user_visited = Vehicle.objects.filter(
            plate_number=plate_number,
            site_name=site
        ).exists()
        
        sites_data.append({
            'name': site,
            'current_occupancy': current_occupancy,
            'today_entries': today_entries,
            'avg_duration': avg_duration,
            'peak_hours': peak_hours_str,
            'typical_fee': typical_fee,
            'status': status,
            'status_text': status_text,
            'status_color': status_color,
            'user_visited': user_visited,
        })
    
    # Sort by status (busy first, then available, then quiet)
    status_order = {'busy': 0, 'available': 1, 'quiet': 2}
    sites_data.sort(key=lambda x: status_order.get(x['status'], 3))
    
    context = {
        'plate_number': plate_number,
        'sites': sites_data,
        'total_sites': len(sites_data),
    }
    
    return render(request, 'owner/availability.html', context)