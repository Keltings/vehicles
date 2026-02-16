from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('', views.dashboard_view, name='dashboard'),
    
    # Analytics
    path('analytics/', views.analytics_overview, name='analytics_overview'),
    path('analytics/sites/', views.site_analytics, name='site_analytics'),
    path('analytics/time/', views.time_analytics, name='time_analytics'),
    path('analytics/vehicles/', views.vehicle_type_analytics, name='vehicle_type_analytics'),
    path('analytics/duration/', views.duration_analytics, name='duration_analytics'),
    
    # Vehicle Behavior
    path('vehicles/', views.vehicle_list, name='vehicle_list'),
    path('vehicles/search/', views.vehicle_search, name='vehicle_search'),
    
    # Alerts
    path('alerts/', views.alerts_center, name='alerts_center'),
    path('api/vehicle/<str:plate_number>/', views.vehicle_detail_api, name='vehicle_detail_api'),
    path('alerts/resolve/<int:flag_id>/', views.resolve_alert, name='resolve_alert'),
    path('watchlist/remove/<int:flag_id>/', views.remove_from_watchlist, name='remove_from_watchlist'),
    path('api/route-vehicles/', views.route_vehicles_api, name='route_vehicles_api'),
    path('api/audit-plate-view/', views.audit_plate_view, name='audit_plate_view'),
    path('export/site-performance/', views.export_site_performance, name='export_site_performance'),
    path('export/vehicle-types/', views.export_vehicle_types, name='export_vehicle_types'),
    path('export/operational-issues/', views.export_operational_issues, name='export_operational_issues'),
    path('audit-logs/', views.audit_logs_view, name='audit_logs'),
    path('export/audit-logs/', views.export_audit_logs, name='export_audit_logs'),
    path('vehicles/', views.vehicle_list, name='vehicle_list'),
    path('export/vehicles/', views.export_vehicles, name='export_vehicles'),
    path('api/search-vehicles/', views.search_vehicles_api, name='search_vehicles_api'),
    path('alerts/create/', views.create_alert, name='create_alert'),
    path('api/resolve-alert/<int:alert_id>/', views.resolve_alert_api, name='resolve_alert_api'),
    path('api/bulk-resolve-alerts/', views.bulk_resolve_alerts, name='bulk_resolve_alerts'),
    path('api/bulk-delete-alerts/', views.bulk_delete_alerts, name='bulk_delete_alerts'),
    path('api/alert-details/<int:alert_id>/', views.alert_details_api, name='alert_details_api'),
    path('alerts/create-rule/', views.create_custom_rule, name='create_custom_rule'),
    path('api/toggle-rule/<int:rule_id>/', views.toggle_rule_api, name='toggle_rule_api'),
    path('api/delete-rule/<int:rule_id>/', views.delete_rule_api, name='delete_rule_api'),
    path('site-intelligence/', views.site_intelligence, name='site_intelligence'),
    path('export/site-report/', views.export_site_report, name='export_site_report'),
]